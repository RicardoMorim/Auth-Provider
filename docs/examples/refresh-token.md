# Refresh Token Examples

Comprehensive examples for implementing refresh tokens in different scenarios.

## ⚠️ Breaking Changes in v3.0.0

- **UUID Primary Keys:** All user IDs are now UUID instead of Long
- **Enhanced Decoupling:** New factory pattern for user creation
- **Repository Types:** Choose between JPA and PostgreSQL implementations
- **CSRF Protection:** Cross-Site Request Forgery protection now enabled by default (NEW)

## ⚠️ Breaking Changes in v2.0.0

- **Token cookies**: Authentication now uses secure cookies for access and refresh tokens, with `httpOnly`, `secure`, and `sameSite` flags by default. **Tokens are not accessible via JavaScript.** The browser will automatically send cookies with requests; your frontend should not attempt to read or write token cookies directly.
- **HTTPS enforcement**: By default, the API only allows HTTPS. To disable, set `ricardo.auth.redirect-https=false`.
- **Blocklist support**: Add `ricardo.auth.token-blocklist` config to enable in-memory or Redis-based token revocation.
- **Rate limiting**: Add `ricardo.auth.rate-limiter` config for in-memory or Redis-based rate limiting.
- **/api/auth/revoke endpoint**: New admin-only endpoint to revoke any access or refresh token.

---

## 📱 Frontend Integration

### React/Next.js Example

**NEW v3.0.0+ with CSRF Protection:**
```javascript
// hooks/useAuth.js
import { useState, useCallback } from 'react';

// Utility function to get CSRF token from cookie
function getCsrfToken() {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'XSRF-TOKEN') {
            return decodeURIComponent(value);
        }
    }
    return null;
}

export const useAuth = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Login function
  const login = async (email, password) => {
    try {
      // Login endpoint doesn't require CSRF token (public endpoint)
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
        credentials: 'include', // Important: send cookies
      });
      if (response.ok) {
        setIsAuthenticated(true);
        return { success: true };
      } else {
        return { success: false, error: 'Invalid credentials' };
      }
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  // Refresh token function (requires CSRF token)
  const refreshAccessToken = useCallback(async () => {
    try {
      const csrfToken = getCsrfToken();
      if (!csrfToken) {
        console.warn('CSRF token not found for refresh request');
        return false;
      }

      const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-XSRF-TOKEN': csrfToken // CSRF token required
        }
      });
      if (response.ok) {
        setIsAuthenticated(true);
        return true;
      } else {
        logout();
        return false;
      }
    } catch (error) {
      logout();
      return false;
    }
  }, []);

  // Logout function
  const logout = async () => {
    try {
      const csrfToken = getCsrfToken();
      const headers = {};
      
      if (csrfToken) {
        headers['X-XSRF-TOKEN'] = csrfToken;
      }

      await fetch('/api/auth/logout', { 
        method: 'POST', 
        credentials: 'include',
        headers
      });
    } catch (e) {
      // Ignore network errors
    }
    setIsAuthenticated(false);
  };

  // API call with automatic token refresh and CSRF protection
  const apiCall = useCallback(async (url, options = {}) => {
    const defaultOptions = {
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      ...options
    };

    // Add CSRF token for state-changing methods
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(options.method?.toUpperCase())) {
      const csrfToken = getCsrfToken();
      if (csrfToken) {
        defaultOptions.headers['X-XSRF-TOKEN'] = csrfToken;
      } else {
        console.warn('CSRF token not found for', options.method, 'request to', url);
      }
    }

    let response = await fetch(url, defaultOptions);
    
    // Handle token expiration
    if (response.status === 401) {
      const refreshed = await refreshAccessToken();
      if (refreshed) {
        // Retry with fresh token and CSRF token
        const newCsrfToken = getCsrfToken();
        if (newCsrfToken && defaultOptions.headers['X-XSRF-TOKEN']) {
          defaultOptions.headers['X-XSRF-TOKEN'] = newCsrfToken;
        }
        response = await fetch(url, defaultOptions);
      }
    }
    
    return response;
  }, [refreshAccessToken]);

  return {
    isAuthenticated,
    login,
    logout,
    apiCall,
  };
};
```

### Vue.js Example

```javascript
// composables/useAuth.js
import { ref, computed } from 'vue';

const isAuthenticated = ref(false);

export const useAuth = () => {
  const login = async (email, password) => {
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
        credentials: 'include',
      });
      if (response.ok) {
        isAuthenticated.value = true;
        return { success: true };
      }
      return { success: false, error: 'Invalid credentials' };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  const refreshTokens = async () => {
    try {
      const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        credentials: 'include',
      });
      if (response.ok) {
        isAuthenticated.value = true;
        return true;
      }
      logout();
      return false;
    } catch (error) {
      logout();
      return false;
    }
  };

  const logout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
    } catch (e) {
      // Ignore network errors
    }
    isAuthenticated.value = false;
  };

  return {
    isAuthenticated,
    login,
    logout,
    refreshTokens,
  };
};
```

### Custom Token Service

```java
@Service
public class TokenService {
    
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;
    
    public TokenService(JwtService jwtService, RefreshTokenRepository refreshTokenRepository) {
        this.jwtService = jwtService;
        this.refreshTokenRepository = refreshTokenRepository;
    }
    
    @Transactional
    public TokenResponse createTokens(User user) {
        // Generate access token
        String accessToken = jwtService.generateToken(user.getEmail(), user.getAuthorities());
        
        // Generate refresh token
        RefreshToken refreshToken = RefreshToken.builder()
            .token(UUID.randomUUID().toString())
            .userId(user.getId())
            .expiresAt(LocalDateTime.now().plusDays(30))
            .build();
        
        refreshTokenRepository.save(refreshToken);
        
        return TokenResponse.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken.getToken())
            .build();
    }
    
    @Transactional
    public TokenResponse refreshTokens(String refreshTokenValue) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenValue)
            .orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        
        if (refreshToken.isExpired()) {
            refreshTokenRepository.delete(refreshToken);
            throw new RuntimeException("Refresh token expired");
        }
        
        // Get user
        User user = userRepository.findById(refreshToken.getUserId())
            .orElseThrow(() -> new RuntimeException("User not found"));
        
        // Delete old refresh token
        refreshTokenRepository.delete(refreshToken);
        
        // Create new tokens
        return createTokens(user);
    }
}
```

## 📱 Mobile App Integration

### Android (Kotlin) Example

```kotlin
// AuthRepository.kt
class AuthRepository {
    private val sharedPrefs = context.getSharedPreferences("auth", Context.MODE_PRIVATE)
    private val httpClient = OkHttpClient()
    
    suspend fun login(email: String, password: String): Result<TokenResponse> {
        val requestBody = """
            {
                "email": "$email",
                "password": "$password"
            }
        """.trimIndent()
        
        val request = Request.Builder()
            .url("$BASE_URL/api/auth/login")
            .post(requestBody.toRequestBody("application/json".toMediaType()))
            .build()
        
        return try {
            val response = httpClient.newCall(request).execute()
            if (response.isSuccessful) {
                val tokenResponse = Gson().fromJson(response.body?.string(), TokenResponse::class.java)
                saveTokens(tokenResponse)
                Result.success(tokenResponse)
            } else {
                Result.failure(Exception("Login failed"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    suspend fun refreshToken(): Result<TokenResponse> {
        val refreshToken = getRefreshToken() ?: return Result.failure(Exception("No refresh token"))
        
        val requestBody = """
            {
                "refreshToken": "$refreshToken"
            }
        """.trimIndent()
        
        val request = Request.Builder()
            .url("$BASE_URL/api/auth/refresh")
            .post(requestBody.toRequestBody("application/json".toMediaType()))
            .build()
        
        return try {
            val response = httpClient.newCall(request).execute()
            if (response.isSuccessful) {
                val tokenResponse = Gson().fromJson(response.body?.string(), TokenResponse::class.java)
                saveTokens(tokenResponse)
                Result.success(tokenResponse)
            } else {
                clearTokens()
                Result.failure(Exception("Token refresh failed"))
            }
        } catch (e: Exception) {
            clearTokens()
            Result.failure(e)
        }
    }
    
    private fun saveTokens(tokenResponse: TokenResponse) {
        sharedPrefs.edit()
            .putString("access_token", tokenResponse.accessToken)
            .putString("refresh_token", tokenResponse.refreshToken)
            .apply()
    }
    
    private fun clearTokens() {
        sharedPrefs.edit()
            .remove("access_token")
            .remove("refresh_token")
            .apply()
    }
}
```

### iOS (Swift) Example

```swift
// AuthService.swift
class AuthService {
    private let baseURL = "https://your-api.com"
    private let userDefaults = UserDefaults.standard
    
    func login(email: String, password: String) async throws -> TokenResponse {
        let url = URL(string: "\(baseURL)/api/auth/login")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let body = [
            "email": email,
            "password": password
        ]
        
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw AuthError.loginFailed
        }
        
        let tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: data)
        saveTokens(tokenResponse)
        return tokenResponse
    }
    
    func refreshToken() async throws -> TokenResponse {
        guard let refreshToken = getRefreshToken() else {
            throw AuthError.noRefreshToken
        }
        
        let url = URL(string: "\(baseURL)/api/auth/refresh")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let body = ["refreshToken": refreshToken]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            clearTokens()
            throw AuthError.tokenRefreshFailed
        }
        
        let tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: data)
        saveTokens(tokenResponse)
        return tokenResponse
    }
    
    private func saveTokens(_ tokenResponse: TokenResponse) {
        userDefaults.set(tokenResponse.accessToken, forKey: "access_token")
        userDefaults.set(tokenResponse.refreshToken, forKey: "refresh_token")
    }
    
    private func clearTokens() {
        userDefaults.removeObject(forKey: "access_token")
        userDefaults.removeObject(forKey: "refresh_token")
    }
}
```

## 🌐 Load Balancer Setup

### NGINX Configuration

```nginx
# nginx.conf
upstream auth_backend {
    server auth-app-1:8080;
    server auth-app-2:8080;
    server auth-app-3:8080;
}

server {
    listen 80;
    server_name api.example.com;
    
    # Auth endpoints - sticky sessions for refresh tokens
    location /api/auth/refresh {
        proxy_pass http://auth_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # Sticky sessions based on refresh token
        hash $request_body consistent;
    }
    
    # Other auth endpoints
    location /api/auth {
        proxy_pass http://auth_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## 🔒 Security Best Practices

### Secure Token Storage

Deprecated: Use secure cookies for token storage instead of localStorage or sessionStorage. This prevents XSS attacks from accessing tokens.

### Request Interceptor

```javascript
// utils/apiClient.js
class ApiClient {
  constructor() {
    this.baseURL = process.env.REACT_APP_API_URL;
    this.secureStorage = new SecureStorage();
  }
  
  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    };
    
    // Add access token if available
    const tokens = this.secureStorage.getTokensEncrypted();
    if (tokens?.accessToken) {
      config.headers.Authorization = `Bearer ${tokens.accessToken}`;
    }
    
    let response = await fetch(url, config);
    
    // Handle token refresh
    if (response.status === 401 && tokens?.refreshToken) {
      const newTokens = await this.refreshTokens(tokens.refreshToken);
      
      if (newTokens) {
        config.headers.Authorization = `Bearer ${newTokens.accessToken}`;
        response = await fetch(url, config);
      }
    }
    
    return response;
  }
  
  async refreshTokens(refreshToken) {
    try {
      const response = await fetch(`${this.baseURL}/api/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken }),
      });
      
      if (response.ok) {
        const tokens = await response.json();
        this.secureStorage.setTokensEncrypted(tokens);
        return tokens;
      }
      
      this.secureStorage.clearTokens();
      return null;
    } catch (error) {
      this.secureStorage.clearTokens();
      return null;
    }
  }
}
```

## 📊 Monitoring and Analytics

### Token Usage Tracking

```java
@Component
public class TokenUsageTracker {
    
    private final MeterRegistry meterRegistry;
    private final Counter tokenRefreshCounter;
    private final Timer tokenRefreshTimer;
    
    public TokenUsageTracker(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
        this.tokenRefreshCounter = Counter.builder("auth.token.refresh")
            .description("Number of token refresh attempts")
            .register(meterRegistry);
        this.tokenRefreshTimer = Timer.builder("auth.token.refresh.duration")
            .description("Token refresh duration")
            .register(meterRegistry);
    }
    
    public void trackTokenRefresh(String result) {
        tokenRefreshCounter.increment(Tags.of("result", result));
    }
    
    public Timer.Sample startTokenRefreshTimer() {
        return Timer.start(meterRegistry);
    }
    
    public void stopTokenRefreshTimer(Timer.Sample sample) {
        sample.stop(tokenRefreshTimer);
    }
}
```

### Grafana Dashboard Query

```promql
# Token refresh rate
rate(auth_token_refresh_total[5m])

# Token refresh success rate
rate(auth_token_refresh_total{result="success"}[5m]) / rate(auth_token_refresh_total[5m])

# Average token refresh duration
rate(auth_token_refresh_duration_seconds_sum[5m]) / rate(auth_token_refresh_duration_seconds_count[5m])
```

## 🧪 Testing

### Unit Tests

```java
@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {
    
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    
    @Mock
    private UserRepository userRepository;
    
    @Mock
    private JwtService jwtService;
    
    @InjectMocks
    private RefreshTokenService refreshTokenService;
    
    @Test
    void shouldRefreshTokenSuccessfully() {
        // Given
        String refreshTokenValue = "valid-refresh-token";
        RefreshToken refreshToken = RefreshToken.builder()
            .token(refreshTokenValue)
            .userId(1L)
            .expiresAt(LocalDateTime.now().plusDays(1))
            .build();
        
        User user = User.builder()
            .id(1L)
            .email("test@example.com")
            .build();
        
        when(refreshTokenRepository.findByToken(refreshTokenValue))
            .thenReturn(Optional.of(refreshToken));
        when(userRepository.findById(1L))
            .thenReturn(Optional.of(user));
        when(jwtService.generateToken(any(), any()))
            .thenReturn("new-access-token");
        
        // When
        TokenResponse result = refreshTokenService.refreshToken(refreshTokenValue);
        
        // Then
        assertThat(result.getAccessToken()).isEqualTo("new-access-token");
        assertThat(result.getRefreshToken()).isNotNull();
        verify(refreshTokenRepository).delete(refreshToken);
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }
}
```

### Integration Tests

```java
@SpringBootTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
class RefreshTokenIntegrationTest {
    
    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:14")
            .withDatabaseName("testdb")
            .withUsername("test")
            .withPassword("test");
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Test
    void shouldHandleCompleteRefreshTokenFlow() {
        // Create user
        CreateUserRequest createRequest = new CreateUserRequest("test@example.com", "password123");
        restTemplate.postForEntity("/api/users/create", createRequest, UserDTO.class);
        
        // Login
        LoginRequest loginRequest = new LoginRequest("test@example.com", "password123");
        ResponseEntity<TokenResponse> loginResponse = restTemplate.postForEntity(
            "/api/auth/login", loginRequest, TokenResponse.class);
        
        assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        TokenResponse tokens = loginResponse.getBody();
        assertThat(tokens.getAccessToken()).isNotNull();
        assertThat(tokens.getRefreshToken()).isNotNull();
        
        // Refresh token
        RefreshTokenRequest refreshRequest = new RefreshTokenRequest(tokens.getRefreshToken());
        ResponseEntity<TokenResponse> refreshResponse = restTemplate.postForEntity(
            "/api/auth/refresh", refreshRequest, TokenResponse.class);
        
        assertThat(refreshResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        TokenResponse newTokens = refreshResponse.getBody();
        assertThat(newTokens.getAccessToken()).isNotNull();
        assertThat(newTokens.getRefreshToken()).isNotNull();
        assertThat(newTokens.getAccessToken()).isNotEqualTo(tokens.getAccessToken());
        assertThat(newTokens.getRefreshToken()).isNotEqualTo(tokens.getRefreshToken());
    }
}
```
