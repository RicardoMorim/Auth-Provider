# Refresh Token Examples

Comprehensive examples for implementing refresh tokens in different scenarios.

## 📱 Frontend Integration

### React/Next.js Example

```javascript
// hooks/useAuth.js
import { useState, useEffect, useCallback } from 'react';

export const useAuth = () => {
  const [tokens, setTokens] = useState({
    accessToken: null,
    refreshToken: null,
  });
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Load tokens from localStorage on mount
  useEffect(() => {
    const accessToken = localStorage.getItem('accessToken');
    const refreshToken = localStorage.getItem('refreshToken');
    
    if (accessToken && refreshToken) {
      setTokens({ accessToken, refreshToken });
      setIsAuthenticated(true);
    }
  }, []);

  // Login function
  const login = async (email, password) => {
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (response.ok) {
        const data = await response.json();
        
        // Store tokens
        localStorage.setItem('accessToken', data.accessToken);
        localStorage.setItem('refreshToken', data.refreshToken);
        
        setTokens(data);
        setIsAuthenticated(true);
        
        return { success: true };
      } else {
        return { success: false, error: 'Invalid credentials' };
      }
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  // Refresh token function
  const refreshAccessToken = useCallback(async () => {
    try {
      const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: tokens.refreshToken }),
      });

      if (response.ok) {
        const data = await response.json();
        
        // Update tokens
        localStorage.setItem('accessToken', data.accessToken);
        localStorage.setItem('refreshToken', data.refreshToken);
        
        setTokens(data);
        return data.accessToken;
      } else {
        // Refresh failed, logout user
        logout();
        return null;
      }
    } catch (error) {
      logout();
      return null;
    }
  }, [tokens.refreshToken]);

  // Logout function
  const logout = () => {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    setTokens({ accessToken: null, refreshToken: null });
    setIsAuthenticated(false);
  };

  // API call with automatic token refresh
  const apiCall = useCallback(async (url, options = {}) => {
    const makeRequest = async (token) => {
      return fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${token}`,
        },
      });
    };

    // Try with current token
    let response = await makeRequest(tokens.accessToken);
    
    // If unauthorized, try refreshing token
    if (response.status === 401) {
      const newToken = await refreshAccessToken();
      if (newToken) {
        response = await makeRequest(newToken);
      }
    }
    
    return response;
  }, [tokens.accessToken, refreshAccessToken]);

  return {
    tokens,
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

const accessToken = ref(localStorage.getItem('accessToken'));
const refreshToken = ref(localStorage.getItem('refreshToken'));

export const useAuth = () => {
  const isAuthenticated = computed(() => !!accessToken.value);

  const login = async (email, password) => {
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (response.ok) {
        const data = await response.json();
        
        accessToken.value = data.accessToken;
        refreshToken.value = data.refreshToken;
        
        localStorage.setItem('accessToken', data.accessToken);
        localStorage.setItem('refreshToken', data.refreshToken);
        
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
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: refreshToken.value }),
      });

      if (response.ok) {
        const data = await response.json();
        
        accessToken.value = data.accessToken;
        refreshToken.value = data.refreshToken;
        
        localStorage.setItem('accessToken', data.accessToken);
        localStorage.setItem('refreshToken', data.refreshToken);
        
        return data.accessToken;
      }
      
      logout();
      return null;
    } catch (error) {
      logout();
      return null;
    }
  };

  const logout = () => {
    accessToken.value = null;
    refreshToken.value = null;
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
  };

  return {
    isAuthenticated,
    login,
    logout,
    refreshTokens,
    accessToken: computed(() => accessToken.value),
  };
};
```

## 🔧 Backend Integration

### Spring Boot Configuration

```yaml
# application.yml
ricardo:
  auth:
    jwt:
      secret: ${JWT_SECRET:your-dev-secret-key}
      access-token-expiration: 900000  # 15 minutes for access tokens
      refresh-token-expiration: 2592000000  # 30 days for refresh tokens
    refresh-tokens:
      enabled: true
      repository:
        type: "postgresql"
      cleanup-interval: 3600000  # Hourly cleanup
      max-tokens-per-user: 5
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

```javascript
// utils/secureStorage.js
class SecureStorage {
  constructor() {
    this.tokenKey = 'auth_tokens';
  }
  
  // Store tokens in httpOnly cookie (recommended)
  setTokens(tokens) {
    document.cookie = `access_token=${tokens.accessToken}; HttpOnly; Secure; SameSite=Strict; Max-Age=900`;
    document.cookie = `refresh_token=${tokens.refreshToken}; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000`;
  }
  
  // Alternative: Secure localStorage with encryption
  setTokensEncrypted(tokens) {
    const encryptedTokens = this.encrypt(JSON.stringify(tokens));
    localStorage.setItem(this.tokenKey, encryptedTokens);
  }
  
  getTokensEncrypted() {
    const encryptedTokens = localStorage.getItem(this.tokenKey);
    if (!encryptedTokens) return null;
    
    try {
      return JSON.parse(this.decrypt(encryptedTokens));
    } catch (error) {
      this.clearTokens();
      return null;
    }
  }
  
  clearTokens() {
    localStorage.removeItem(this.tokenKey);
    document.cookie = 'access_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    document.cookie = 'refresh_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
  }
  
  encrypt(text) {
    // Use a proper encryption library like crypto-js
    return CryptoJS.AES.encrypt(text, this.getEncryptionKey()).toString();
  }
  
  decrypt(ciphertext) {
    const bytes = CryptoJS.AES.decrypt(ciphertext, this.getEncryptionKey());
    return bytes.toString(CryptoJS.enc.Utf8);
  }
}
```

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

