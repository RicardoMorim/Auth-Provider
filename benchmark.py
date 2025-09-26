import requests
import time
import statistics
import csv
import uuid
import psutil
import json
import threading
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from datetime import datetime
from urllib.parse import quote

# --- Configuration ---
BASE_URL = "http://localhost:8080"
USERNAME = "ricardoatm28@gmail.com"
PASSWORD = "Ricardo@28"

# --- Stress Test Parameters ---
# Dataset Creation
DATASET_SIZE = 100000  # Number of users to create and KEEP

# Sequential Test
SEQUENTIAL_REQUESTS = 60000

# Concurrent Test
CONCURRENT_THREADS = 4
CONCURRENT_TOTAL_REQUESTS = 100000

# Query/Update Tests (Using existing users from the dataset)
QUERY_UPDATE_COUNT = 60000

# --- End Configuration ---

CSV_DIR = "benchmark_results"

# Global variables for tracking
benchmark_user_details_pool = [] # List of dicts {'username': '...', 'email': '...'}
benchmark_user_details_pool_lock = threading.Lock()

created_users_for_cleanup = [] # For users created by tests like security tests
created_users_for_cleanup_lock = threading.Lock()

test_start_time = None
main_csrf_token_value = None
main_session_cookies = None

def setup_directories():
    import os
    if not os.path.exists(CSV_DIR):
        os.makedirs(CSV_DIR)

def get_memory_usage():
    process = psutil.Process()
    return process.memory_info().rss / 1024 / 1024

def get_csrf_token_value(session):
    try:
        r = session.get(f"{BASE_URL}/api/csrf-token", timeout=10)
        r.raise_for_status()
        try:
            data = r.json()
            if isinstance(data, dict) and 'token' in data:
                return data['token']
            else:
                return data
        except json.JSONDecodeError:
            return r.text.strip('"')
    except Exception as e:
        print(f"Error fetching CSRF token using session {id(session)}: {e}")
        print(f"  Response status: {r.status_code if 'r' in locals() else 'N/A'}")
        raise

def login():
    global main_csrf_token_value, main_session_cookies
    session = requests.Session()

    try:
        initial_csrf_token = get_csrf_token_value(session)
        print(f"Initial CSRF token for login obtained: {initial_csrf_token[:20]}...")
    except Exception as e:
        print(f"Failed to get initial CSRF token for login: {e}")
        raise

    payload = {"email": USERNAME, "password": PASSWORD}

    try:
        r = session.post(
            f"{BASE_URL}/api/auth/login",
            json=payload,
            headers={'X-XSRF-TOKEN': initial_csrf_token},
            timeout=10
        )
        r.raise_for_status()

        print(f"Login successful for session {id(session)}. Status: {r.status_code}")
        print(f"Session cookies after login: {dict(session.cookies)}")

        main_csrf_token_value = get_csrf_token_value(session)
        main_session_cookies = session.cookies.copy()
        print(f"Main CSRF token and cookies stored globally.")
        return session
    except Exception as e:
        print(f"Login failed: {e}")
        print(f"Response status: {r.status_code if 'r' in locals() else 'N/A'}, Response text: {r.text if 'r' in locals() else 'N/A'}")
        raise

def timed_request(method, url, test_name="", add_csrf=True, use_public_session=False, **kwargs):
    start = time.perf_counter()
    thread_id = threading.current_thread().ident
    timestamp = datetime.now().isoformat()

    if use_public_session:
        session = requests.Session()
    else:
        session = requests.Session()
        if main_session_cookies:
            session.cookies.update(main_session_cookies)
        if add_csrf and main_csrf_token_value:
             if 'headers' not in kwargs:
                kwargs['headers'] = {}
             kwargs['headers']['X-XSRF-TOKEN'] = main_csrf_token_value

    try:
        r = session.request(method, url, timeout=15, **kwargs)
        elapsed = time.perf_counter() - start

        response_size = len(r.content) if hasattr(r, 'content') else 0

        return {
            'test_name': test_name,
            'status_code': r.status_code,
            'latency': elapsed,
            'response_size': response_size,
            'error': None if r.status_code < 400 else f"{r.status_code} - {r.reason}",
            'thread_id': thread_id,
            'timestamp': timestamp,
            'memory_mb': get_memory_usage(),
            'session_id': id(session)
        }
    except Exception as e:
        elapsed = time.perf_counter() - start
        return {
            'test_name': test_name,
            'status_code': 0,
            'latency': elapsed,
            'response_size': 0,
            'error': str(e),
            'thread_id': thread_id,
            'timestamp': timestamp,
            'memory_mb': get_memory_usage(),
            'session_id': id(session)
        }

# --- Helper functions for stats ---
def calculate_throughput(results, test_name_filter=""):
    if test_name_filter:
        test_results = [r for r in results if test_name_filter in r['test_name'] and r['status_code'] == 200]
    else:
        test_results = [r for r in results if r['status_code'] == 200]

    if not test_results:
        return 0

    timestamps = [datetime.fromisoformat(r['timestamp']) for r in test_results]
    if len(timestamps) < 2:
        return len(test_results)

    duration = (max(timestamps) - min(timestamps)).total_seconds()
    return len(test_results) / max(duration, 0.001)

def calculate_success_rate(results, test_name_filter=""):
    if test_name_filter:
        test_results = [r for r in results if test_name_filter in r['test_name']]
    else:
        test_results = results

    if not test_results:
        return 0

    successful = len([r for r in test_results if r['status_code'] == 200])
    return (successful / len(test_results)) * 100

def print_detailed_stats(name, results):
    test_results = [r for r in results if name in r['test_name']]
    if not test_results:
        print(f"\n{name} - No results found")
        return

    successful_results = [r for r in test_results if r['status_code'] == 200]
    times = [r['latency'] for r in successful_results]

    if not times:
        print(f"\n{name} - No successful requests")
        return

    throughput = calculate_throughput(results, name)
    success_rate = calculate_success_rate(results, name)

    print(f"\n{name} Stats:")
    print(f"  Requests: {len(test_results)} (Success: {len(successful_results)})")
    print(f"  Success Rate: {success_rate:.2f}%")
    print(f"  Throughput: {throughput:.2f} req/s")
    print(f"  Latency Stats:")
    print(f"    Avg: {statistics.mean(times):.4f}s")
    print(f"    Min: {min(times):.4f}s")
    print(f"    Max: {max(times):.4f}s")

    if len(times) >= 2:
        try:
            print(f"    P50: {statistics.median(times):.4f}s")
            print(f"    P90: {statistics.quantiles(times, n=100)[89]:.4f}s")
            print(f"    P95: {statistics.quantiles(times, n=100)[94]:.4f}s")
            print(f"    P99: {statistics.quantiles(times, n=100)[98]:.4f}s")
        except Exception as e:
            print(f"    Could not calculate percentiles: {e}")

def save_results_to_csv(results, filename):
    filepath = f"{CSV_DIR}/{filename}"
    with open(filepath, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Test Name", "Status Code", "Latency (s)", "Response Size (bytes)",
            "Error", "Thread ID", "Timestamp", "Memory (MB)", "Session ID"
        ])

        for result in results:
            writer.writerow([
                result['test_name'],
                result['status_code'],
                f"{result['latency']:.6f}",
                result['response_size'],
                result['error'] or "",
                result['thread_id'],
                result['timestamp'],
                f"{result['memory_mb']:.2f}",
                result['session_id']
            ])
    print(f"Results saved to {filepath}")

def fetch_db_metrics(session):
    """Fetches database metrics from the backend service."""
    try:
        # Use the authenticated session to fetch metrics
        r = session.get(f"{BASE_URL}/api/users/metrics/db-operations", timeout=30)
        r.raise_for_status()
        return r.json() # Expecting a list of operation records
    except Exception as e:
        print(f"Warning: Could not fetch DB metrics: {e}")
        return []

def analyze_db_metrics(db_operations):
    """Analyzes the fetched database operations and returns summary statistics."""
    if not db_operations:
        return {"error": "No database operations data available"}

    try:
        successful_ops = [op for op in db_operations if op.get('success', False)]
        failed_ops = [op for op in db_operations if not op.get('success', True)]

        durations = [(op['endTime'] - op['startTime']) for op in successful_ops if 'startTime' in op and 'endTime' in op]

        if not durations:
             return {"error": "No valid duration data in database operations"}

        total_ops = len(db_operations)
        success_rate = (len(successful_ops) / total_ops) * 100 if total_ops > 0 else 0

        summary = {
            'total_operations': total_ops,
            'successful_operations': len(successful_ops),
            'failed_operations': len(failed_ops),
            'db_success_rate_percent': success_rate,
            'avg_db_duration_ms': statistics.mean(durations),
            'min_db_duration_ms': min(durations),
            'max_db_duration_ms': max(durations),
            'p50_db_duration_ms': statistics.median(durations),
        }

        # Add P90, P95, P99 if enough data
        if len(durations) >= 100:
             try:
                 summary['p90_db_duration_ms'] = statistics.quantiles(durations, n=100)[89]
                 summary['p95_db_duration_ms'] = statistics.quantiles(durations, n=100)[94]
                 summary['p99_db_duration_ms'] = statistics.quantiles(durations, n=100)[98]
             except Exception:
                 # Quantiles might fail for specific data distributions
                 pass
        elif durations:
            # If less than 100 but not empty, use max for higher percentiles as approximation
            summary['p90_db_duration_ms'] = max(durations)
            summary['p95_db_duration_ms'] = max(durations)
            summary['p99_db_duration_ms'] = max(durations)

        # Operation type breakdown (optional but useful)
        op_type_counts = defaultdict(int)
        op_type_durations = defaultdict(list)
        for op in successful_ops:
             op_type = op.get('operation', 'unknown')
             op_type_counts[op_type] += 1
             if 'startTime' in op and 'endTime' in op:
                 op_type_durations[op_type].append(op['endTime'] - op['startTime'])

        summary['operation_types'] = {}
        for op_type, count in op_type_counts.items():
            type_avg_duration = statistics.mean(op_type_durations[op_type]) if op_type_durations[op_type] else 0
            summary['operation_types'][op_type] = {
                'count': count,
                'avg_duration_ms': type_avg_duration
            }

        return summary

    except Exception as e:
        return {"error": f"Error analyzing DB metrics: {e}"}

def save_summary_stats(all_results, db_metrics_summary=None):
    summary = {}

    test_groups = defaultdict(list)
    for result in all_results:
        key_parts = result['test_name'].split(' ', 1)[0].split('(', 1)[0]
        test_groups[key_parts].append(result)

    for test_type, results in test_groups.items():
        successful = [r for r in results if r['status_code'] == 200]
        times = [r['latency'] for r in successful]

        if times:
            summary[test_type] = {
                'total_requests': len(results),
                'successful_requests': len(successful),
                'success_rate_percent': calculate_success_rate(all_results, test_type),
                'throughput_rps': calculate_throughput(all_results, test_type),
                'avg_latency_ms': statistics.mean(times) * 1000,
                'min_latency_ms': min(times) * 1000,
                'max_latency_ms': max(times) * 1000,
                'p50_latency_ms': statistics.median(times) * 1000,
                'p90_latency_ms': statistics.quantiles(times, n=100)[89] * 1000 if len(times) >= 100 else (max(times) * 1000 if times else 0),
                'p95_latency_ms': statistics.quantiles(times, n=100)[94] * 1000 if len(times) >= 100 else (max(times) * 1000 if times else 0),
                'p99_latency_ms': statistics.quantiles(times, n=100)[98] * 1000 if len(times) >= 100 else (max(times) * 1000 if times else 0),
            }
        else:
            summary[test_type] = {
                'total_requests': len(results),
                'successful_requests': 0,
                'success_rate_percent': calculate_success_rate(results),
                'throughput_rps': 0,
                'avg_latency_ms': 0,
                'min_latency_ms': 0,
                'max_latency_ms': 0,
                'p50_latency_ms': 0,
                'p90_latency_ms': 0,
                'p95_latency_ms': 0,
                'p99_latency_ms': 0,
            }

    # Add DB metrics summary if available
    if db_metrics_summary:
        summary['Database_Metrics'] = db_metrics_summary

    with open(f"{CSV_DIR}/summary_stats.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Summary statistics saved to {CSV_DIR}/summary_stats.json")

# --- Test functions ---
def create_benchmark_dataset(results):
    global benchmark_user_details_pool
    print(f"\nRunning Benchmark Dataset Creation Test (Creating {DATASET_SIZE} users concurrently)...")
    dataset_results = []
    local_created_users = []
    failed_creations = 0

    print(f"  Creating {DATASET_SIZE} users using {min(CONCURRENT_THREADS, 10)} threads...")

    def create_single_user(i):
        username = f"benchmark_user_{uuid.uuid4().hex[:12]}_{i}"
        new_user = {
            "username": username,
            "email": f"{username}@benchmark.test",
            "password": "Test@1234"
        }
        result = timed_request("POST", f"{BASE_URL}/api/users/create",
                             test_name="Dataset Creation POST /users/create",
                             add_csrf=True, use_public_session=False,
                             json=new_user)
        return result, username

    creation_threads = min(CONCURRENT_THREADS, 10) # Reasonable number for creation
    with ThreadPoolExecutor(max_workers=creation_threads) as executor:
        future_to_index = {executor.submit(create_single_user, i): i for i in range(DATASET_SIZE)}

        for future in as_completed(future_to_index):
            try:
                result, username = future.result()
                dataset_results.append(result)
                results.append(result)

                if result['status_code'] in [200, 201]:
                    user_details = {"username": username, "email": f"{username}@benchmark.test"}
                    local_created_users.append(user_details)
                    with benchmark_user_details_pool_lock:
                        benchmark_user_details_pool.append(user_details)
                    with created_users_for_cleanup_lock:
                        created_users_for_cleanup.append(username)
                else:
                    failed_creations += 1
                    # Optional: print(f"    Warning: Failed to create user {username}. Status: {result['status_code']}")

            except Exception as exc:
                failed_creations += 1
                error_result = {
                    'test_name': "Dataset Creation POST /users/create",
                    'status_code': 0,
                    'latency': 0,
                    'response_size': 0,
                    'error': f"Exception during creation: {exc}",
                    'thread_id': threading.current_thread().ident,
                    'timestamp': datetime.now().isoformat(),
                    'memory_mb': get_memory_usage(),
                    'session_id': 0
                }
                dataset_results.append(error_result)
                results.append(error_result)
                # print(f'    Exception during user creation: {exc}')

    success_count = len(local_created_users)
    print(f"  Dataset creation complete. Successfully created {success_count}/{DATASET_SIZE} users ({failed_creations} failed).")

    print_detailed_stats("Dataset Creation", dataset_results)
    return 20

def re_login_for_tests():
    """Perform a fresh login to get a new valid token before stress tests."""
    global main_csrf_token_value, main_session_cookies
    print("\n--- Re-logging in to get a fresh authentication token for stress tests ---")
    try:
        # Use the existing login function
        temp_session = login()
        # Update the global state with the new session's tokens/cookies
        main_csrf_token_value = get_csrf_token_value(temp_session)
        main_session_cookies = temp_session.cookies.copy()
        print("✓ Re-login successful. Tokens updated for stress tests.")
        return temp_session # Return session for potential metric fetching
    except Exception as e:
        print(f"Re-login failed: {e}. Stress tests might fail due to expired tokens.")
        raise # Re-raise to stop the benchmark if re-login fails

def generate_varied_requests(user_pool, num_requests):
    """Generator that yields varied requests."""
    if not user_pool:
        print("Warning: User pool is empty.")
        return

    # Define the endpoints to test
    endpoints = [
        ("GET", f"{BASE_URL}/api/users", "GET All Users"),
        ("GET", f"{BASE_URL}/api/auth/me", "GET Authenticated User"),
    ]

    pool_size = len(user_pool)
    for i in range(num_requests):
        # Select a user
        selected_user = user_pool[i % pool_size] if pool_size > 0 else {"username": "dummy", "email": "dummy@test.com"}

        # Select a random endpoint that might use the user
        method, base_url_template, test_name_suffix = random.choice(endpoints)

        # Format the URL if it's a template (though our current ones don't need it)
        # url = base_url_template.format(**selected_user) if '{' in base_url_template else base_url_template
        url = base_url_template

        yield method, url, test_name_suffix

def sequential_test(results, num_requests=SEQUENTIAL_REQUESTS):
    print(f"\nRunning Varied Sequential Test ({num_requests} requests)...")
    test_results = []

    request_generator = generate_varied_requests(benchmark_user_details_pool, num_requests)

    for method, url, test_name_suffix in request_generator:
        result = timed_request(method, url,
                             test_name=f"Varied Sequential {test_name_suffix}",
                             add_csrf=True, use_public_session=False)
        test_results.append(result)
        results.append(result)

    print_detailed_stats("Varied Sequential", test_results)
    return 20

def concurrent_test(results, total_requests=CONCURRENT_TOTAL_REQUESTS):
    print(f"\nRunning Varied Concurrent Test ({total_requests} requests)...")
    concurrent_results = []

    # Pre-generate a list of requests to avoid generator issues across threads
    with benchmark_user_details_pool_lock:
        pool_snapshot = benchmark_user_details_pool[:]
    requests_list = list(generate_varied_requests(pool_snapshot, total_requests))

    # Create a thread-safe iterator
    requests_iter = iter(requests_list)
    requests_iter_lock = threading.Lock()

    def make_single_request():
        # Safely get the next request
        with requests_iter_lock:
            try:
                method, url, test_name_suffix = next(requests_iter)
            except StopIteration:
                return None # No more requests

        # Make the timed request
        return timed_request(method, url,
                           test_name=f"Varied Concurrent {test_name_suffix}",
                           add_csrf=True, use_public_session=False)

    with ThreadPoolExecutor(max_workers=CONCURRENT_THREADS) as executor:
        # Submit tasks
        futures = [executor.submit(make_single_request) for _ in range(len(requests_list))]
        for future in as_completed(futures):
            result = future.result()
            if result: # Check if a result was actually produced
                concurrent_results.append(result)
                results.append(result)

    print_detailed_stats("Varied Concurrent", concurrent_results)
    return 20

def query_and_update_test(results):
    print("\nRunning Query and Update Test (using benchmark dataset)...")
    query_update_results = []

    users_to_test = []
    with benchmark_user_details_pool_lock:
        users_to_test = benchmark_user_details_pool[:min(QUERY_UPDATE_COUNT, len(benchmark_user_details_pool))]

    if not users_to_test:
        print("  Warning: No users found in benchmark pool. Skipping query/update tests.")
        return 5

    print(f"  Testing with {len(users_to_test)} users.")

    # 1. Query Users (Check existence)
    print("  Querying user existence...")
    for user_details in users_to_test:
        email = user_details['email']
        result = timed_request("GET", f"{BASE_URL}/api/users/exists/{email}",
                             test_name="Query/Update GET /users/exists",
                             add_csrf=False, use_public_session=False)
        query_update_results.append(result)
        results.append(result)

    # 2. Update Users (using main authenticated session)
    print("  Updating users...")
    for user_details in users_to_test:
         username = user_details['username']
         update_data = {
             "username": username,
             "email": f"updated_{username}@benchmark.test"
         }
         result = timed_request("PUT", f"{BASE_URL}/api/users/update/{username}",
                             test_name="Query/Update PUT /users/update",
                             add_csrf=True, use_public_session=False,
                             json=update_data)
         query_update_results.append(result)
         results.append(result)

    print_detailed_stats("Query and Update", query_update_results)
    return 20

def authentication_overhead_test(results):
    print("\nRunning Authentication Overhead Test...")
    auth_overhead_results = []

    public_session = requests.Session()
    public_times = []
    for i in range(20):
        start = time.perf_counter()
        timestamp = datetime.now().isoformat()
        try:
            r = public_session.get(f"{BASE_URL}/api/csrf-token", timeout=10)
            elapsed = time.perf_counter() - start
            res = {
                'test_name': "Public GET /csrf-token",
                'status_code': r.status_code,
                'latency': elapsed,
                'response_size': len(r.content),
                'error': None if r.status_code < 400 else f"{r.status_code} - {r.reason}",
                'thread_id': threading.current_thread().ident,
                'timestamp': timestamp,
                'memory_mb': get_memory_usage(),
                'session_id': id(public_session)
            }
            auth_overhead_results.append(res)
            results.append(res)
            if r.status_code == 200:
                public_times.append(elapsed)
        except Exception as e:
            elapsed = time.perf_counter() - start
            res = {
                'test_name': "Public GET /csrf-token",
                'status_code': 0,
                'latency': elapsed,
                'response_size': 0,
                'error': str(e),
                'thread_id': threading.current_thread().ident,
                'timestamp': timestamp,
                'memory_mb': get_memory_usage(),
                'session_id': id(public_session)
            }
            auth_overhead_results.append(res)
            results.append(res)

    auth_times = []
    for i in range(20):
        result = timed_request("GET", f"{BASE_URL}/api/auth/me",
                             test_name="Authenticated GET /auth/me",
                             add_csrf=True, use_public_session=False)
        auth_overhead_results.append(result)
        results.append(result)
        if result['status_code'] == 200:
            auth_times.append(result['latency'])

    if public_times and auth_times:
        try:
            public_avg = statistics.mean(public_times)
            auth_avg = statistics.mean(auth_times)
            overhead = ((auth_avg - public_avg) / public_avg) * 100 if public_avg > 0 else float('inf')
            print(f"Authentication overhead: {overhead:.2f}% ({auth_avg - public_avg:.4f}s)")
        except (statistics.StatisticsError, ZeroDivisionError):
            print("Could not calculate authentication overhead.")

    print_detailed_stats("Authentication Overhead", auth_overhead_results)
    return 20

def token_security_test(results):
    """
    Tests CSRF protection on an authenticated endpoint.
    1. Attempts to update a user with an invalid CSRF token (should fail).
    2. Attempts to update a user with a valid CSRF token (should succeed).
    3. Attempts to update a user without a CSRF token (should fail).
    """
    print("\nRunning Token Security Test (Authenticated Endpoint)...")
    security_results = []

    # --- 1. Prepare: Get a valid user to update ---
    # We'll use the first user from the benchmark pool.
    # In a real scenario, you might want to create a dedicated test user.
    if not benchmark_user_details_pool:
        print("  Warning: No users available for CSRF security test.")
        return 5 # Sleep time

    # Use the main authenticated session (which should have valid cookies and CSRF)
    test_user_details = benchmark_user_details_pool[0]
    test_username = test_user_details['username']
    print(f"  Testing CSRF protection for user: {test_username}")

    # --- 2. Test with Invalid CSRF Token ---
    print("  Testing with INVALID CSRF token...")
    invalid_token = "definitely_not_a_valid_csrf_token_12345"
    update_payload_invalid = {
        "username": test_username,
        "email": f"invalid_token_test_{uuid.uuid4().hex[:8]}@test.com"
    }
    # Use the main session but override the CSRF token header
    result_invalid = timed_request(
        "PUT",
        f"{BASE_URL}/api/users/update/{test_username}",
        test_name="CSRF Security Test - Invalid Token",
        add_csrf=False, # Don't use the global valid token
        use_public_session=False, # Use the main authenticated session
        headers={"X-XSRF-TOKEN": invalid_token}, # Inject invalid token
        json=update_payload_invalid
    )
    security_results.append(result_invalid)
    results.append(result_invalid)
    print(f"    Invalid Token Test Status: {result_invalid['status_code']}")

    # --- 3. Test WITHOUT CSRF Token ---
    print("  Testing WITHOUT CSRF token...")
    update_payload_no_token = {
        "username": test_username,
        "email": f"no_token_test_{uuid.uuid4().hex[:8]}@test.com"
    }
    # Use the main session but explicitly disable CSRF addition
    result_no_token = timed_request(
        "PUT",
        f"{BASE_URL}/api/users/update/{test_username}",
        test_name="CSRF Security Test - No Token",
        add_csrf=False, # Don't add any CSRF token
        use_public_session=False, # Use the main authenticated session
        json=update_payload_no_token
        # No X-XSRF-TOKEN header will be added
    )
    security_results.append(result_no_token)
    results.append(result_no_token)
    print(f"    No Token Test Status: {result_no_token['status_code']}")

    # --- 4. Test with VALID CSRF Token ---
    print("  Testing with VALID CSRF token...")
    update_payload_valid = {
        "username": test_username,
        "email": f"valid_token_test_{uuid.uuid4().hex[:8]}@test.com" # Use a unique email
    }
    # Use the standard timed_request which will add the global valid CSRF token
    result_valid = timed_request(
        "PUT",
        f"{BASE_URL}/api/users/update/{test_username}",
        test_name="CSRF Security Test - Valid Token",
        add_csrf=True, # Use the global valid token
        use_public_session=False, # Use the main authenticated session
        json=update_payload_valid
    )
    security_results.append(result_valid)
    results.append(result_valid)
    print(f"    Valid Token Test Status: {result_valid['status_code']}")

    print_detailed_stats("Token Security", security_results)
    return 5 # Sleep time

# --- Main function ---
def main():
    global test_start_time, benchmark_user_details_pool
    test_start_time = time.time()

    print("Starting Comprehensive API Benchmarking Suite")
    print(f"Target: {BASE_URL}")
    print(f"Dataset Size: {DATASET_SIZE}")
    print(f"Sequential Requests: {SEQUENTIAL_REQUESTS}")
    print(f"Concurrent Threads: {CONCURRENT_THREADS}, Total Requests: {CONCURRENT_TOTAL_REQUESTS}")
    print(f"Query/Update Count: {QUERY_UPDATE_COUNT}")

    setup_directories()

    try:
        # 1. Initial Login
        main_session = login()
        print("✓ Initial authentication successful.")

        # CRITICAL UPDATE: Fetch CSRF token AFTER login to ensure it's associated with the authenticated session
        # The previous `login()` function fetched it, but let's make sure `main_csrf_token_value` is set correctly here too.
        # This reinforces that subsequent requests use a CSRF token tied to the login session.
        try:
            main_csrf_token_value = get_csrf_token_value(main_session)
            print(f"✓ Main CSRF token re-fetched and confirmed after login.")
        except Exception as e:
             print(f"Warning: Could not re-fetch CSRF token after login: {e}. Tests might fail if CSRF is required.")
             # Depending on your backend, this might be critical. Let's continue for now.

        all_results = []

        sleep_time = create_benchmark_dataset(all_results)
        print(f"\n--- Completed Benchmark Dataset Creation Test. ---")
        print(f"Sleeping for {sleep_time} seconds...")
        time.sleep(sleep_time)

        if not benchmark_user_details_pool:
             print("Warning: Benchmark dataset appears empty.")
             return
        else:
             print(f"Proceeding with tests using {len(benchmark_user_details_pool)} users.")

        # 2. Re-login to ensure fresh token for subsequent tests and get a session for metrics
        # Also ensures main_csrf_token_value and main_session_cookies are updated.
        metrics_session = re_login_for_tests()

        # 3. Run Stress and Other Tests
        test_functions_and_sleeps = [
            (lambda: sequential_test(all_results, num_requests=SEQUENTIAL_REQUESTS), 10),
            (lambda: concurrent_test(all_results, total_requests=CONCURRENT_TOTAL_REQUESTS), 15),
            (lambda: query_and_update_test(all_results), 10),
            (lambda: authentication_overhead_test(all_results), 5),
            (lambda: token_security_test(all_results), 5), # Updated test
        ]

        for i, (test_func, sleep_time) in enumerate(test_functions_and_sleeps):
            test_func() # Execute the test function
            test_name = test_func.__name__.replace('_', ' ').title()
            print(f"\n--- Completed {test_name}. ---")

            # Sleep between tests, except after the last one
            if i < len(test_functions_and_sleeps) - 1:
                print(f"Sleeping for {sleep_time} seconds...")
                time.sleep(sleep_time)
            else:
                print("This was the last test, no final sleep.")

        # 4. Fetch and analyze database metrics AFTER tests
        print("\n--- Fetching Database Metrics ---")
        db_operations_data = fetch_db_metrics(metrics_session)
        db_metrics_summary = analyze_db_metrics(db_operations_data)
        print(f"DB Metrics Summary: {db_metrics_summary}")

        # 5. Save Results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_results_to_csv(all_results, f"benchmark_results_{timestamp}.csv")

        # Pass the DB metrics summary to the save function
        save_summary_stats(all_results, db_metrics_summary)

        print(f"\n{'='*60}")
        print("COMPREHENSIVE BENCHMARK SUMMARY")
        print(f"{'='*60}")
        print(f"Total Requests: {len(all_results)}")
        print(f"Total Duration: {time.time() - test_start_time:.2f} seconds")
        print(f"Overall Success Rate: {calculate_success_rate(all_results):.2f}%")
        print(f"Overall Throughput: {calculate_throughput(all_results):.2f} req/s")
        print(f"Users in Benchmark Pool: {len(benchmark_user_details_pool)}")

        # 6. Final Cleanup (users created by security tests, etc.)
        if created_users_for_cleanup:
            print(f"\nFinal cleanup: Attempting to delete {len(created_users_for_cleanup)} users created by tests...")
            cleanup_session = requests.Session()
            if main_session_cookies:
                cleanup_session.cookies.update(main_session_cookies)

            users_to_remove = []
            with created_users_for_cleanup_lock:
                 users_to_remove = created_users_for_cleanup[:]

            cleanup_count = 0
            for username in users_to_remove:
                try:
                    headers = {}
                    if main_csrf_token_value:
                        headers['X-XSRF-TOKEN'] = main_csrf_token_value

                    r = cleanup_session.delete(f"{BASE_URL}/api/users/delete/{username}", headers=headers, timeout=5)
                    if r.status_code in [200, 204]:
                        cleanup_count += 1
                        with created_users_for_cleanup_lock:
                            if username in created_users_for_cleanup:
                                created_users_for_cleanup.remove(username)
                except Exception as e:
                     print(f"  Error deleting user {username}: {e}")

            print(f"  Successfully deleted {cleanup_count} out of {len(users_to_remove)} users requiring cleanup.")

        print(f"\n✓ Benchmarking completed! Results saved in {CSV_DIR}/")
        print(f"Note: {len(benchmark_user_details_pool)} benchmark users remain in the database.")

    except Exception as e:
        print(f"Benchmarking failed: {e}")
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    main()