# Benchmark Comparison: With Indexes vs. Without Indexes

This document compares the results of two benchmarks run on the Auth Provider project, one with database indexes and
cache active, and another without them.

## Test Overview

Both tests followed the same plan:

- **Dataset Creation:** 100,000 users
- **Sequential Test:** 60,000 requests
- **Concurrent Test:** 100,000 requests, 4 threads
- **Query/Update Test:** 120,000 requests (60,000 `exists`, 60,000 `update`)

## Results Comparison

### 1. Stability and Success Rate

| Metric                   | With Indexes & Cache | Without Indexes |
|--------------------------|----------------------|-----------------|
| **Overall Success Rate** | **88.16%**           | **73.69%**      |
| **500 Errors (Server)**  | 0                    | 0               |
| **Concurrent Errors**    | ~45,000 (Client)     | 0 (Client)      |

**Note:** The "with indexes" test had a bottleneck in the Python client (Windows TCP port exhaustion), causing many
failures. The "without indexes" test did not have this client issue, perhaps due to it being slower, which allowed 
windows to have more time to clean up the TCP ports.

### 2. User Creation Performance (Write)

| Metric                               | With Indexes & Cache | Without Indexes |
|--------------------------------------|----------------------|-----------------|
| **Average Latency (ms)**             | ~145 ms              | ~145 ms         |
| **Median Latency (ms)**              | ~144 ms              | ~143 ms         |
| **Total Time (approx., s)**          | ~3639 s              | ~3639 s         |
| **Write RPS**                        | ~27.5 req/s          | ~27.5 req/s     |
| **Avg `createUser` DB Latency (ms)** | ~1.42 ms             | ~1.46 ms        |

**Result:** Creation performance was **virtually identical**. The absence of indexes did not bring a significant speed
gain for pure write operations in this benchmark.

### 3. Read Performance (Sequential)

| Metric                                | With Indexes & Cache | Without Indexes |
|---------------------------------------|----------------------|-----------------|
| **Average Latency (ms)**              | **~21 ms**           | **~27 ms**      |
| **Median Latency (ms)**               | **~23 ms**           | **~31 ms**      |
| **Sequential Read RPS**               | **~46.7 req/s**      | **~36.7 req/s** |
| **Avg `userExists` DB Latency (ms)**  | **~0.29 ms**         | **~0.30 ms**    |
| **Avg `getUserById` DB Latency (ms)** | **~0.24 ms**         | **~0.19 ms**    |
| **Avg `getAllUsers` DB Latency (ms)** | **~0.38 ms**         | **~28 ms**      |

**Result:** Read performance was **significantly worse** without indexes. Average latency increased by ~22% and
throughput dropped by ~21%. The listing/pagination operation (`getAllUsers`) became **~73 times slower**.

### 4. Mixed Query/Update Performance

| Metric                   | With Indexes & Cache | Without Indexes |
|--------------------------|----------------------|-----------------|
| **Average Latency (ms)** | ~30 ms               | **~24 ms**      |
| **Throughput (RPS)**     | ~33.3 req/s          | **~41.4 req/s** |

**Result:** Interestingly, this test showed a slight **improvement** in latency and throughput. This might be related to
other factors or the specific profile of this test.

### 5. Performance Under Concurrent Load (Stress Test)

| Metric                                   | With Indexes & Cache | Without Indexes  |
|------------------------------------------|----------------------|------------------|
| **Success Rate**                         | 55% (due to client)  | **100%**         |
| **Successful Requests Throughput (RPS)** | ~139 req/s           | **~122.8 req/s** |
| **Avg Successful Request Latency (ms)**  | ~16 ms               | **~32 ms**       |

**Result:** Without the client bottleneck, the full concurrent test showed that the backend without indexes is *
*significantly slower** at processing individual requests under load.

### 6. Overall Database Metrics

| Metric                  | With Indexes & Cache | Without Indexes |
|-------------------------|----------------------|-----------------|
| **Avg DB Latency (ms)** | **~0.8 ms**          | **~6.0 ms**     |
| **DB P99 Latency (ms)** | **~6 ms**            | **~46 ms**      |

**Result:** Overall database performance was **substantially degraded** without indexes, both in average latency and for
slower operations.

## Conclusion

The benchmark comparison clearly confirms the classic database index trade-off:

- **There was no significant improvement in write performance (user creation)**. It was virtually identical.
- **There was a catastrophic degradation in performance for queries requiring scans or sorts on large datasets** (like
  pagination/listing), making them dozens of times slower.
- This negatively impacted the overall performance of sequential read operations.
- Under concurrent load, the backend without indexes was significantly slower to respond to individual requests.
- Overall database performance was considerably worse.

Therefore, database indexes are **critical** for read performance on large datasets, even though the expected speed gain
for raw `INSERT` speed was not dramatically observed in the final benchmark metrics. The stability of throughput and
latency under load is clearly impaired by the absence of indexes.
