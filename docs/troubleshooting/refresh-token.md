# Refresh Token Troubleshooting

Common issues and solutions for refresh token functionality.

## 🔍 Quick Diagnosis

### Check if Refresh Tokens are Enabled

```yaml
# application.yml
ricardo:
  auth:
    refresh-tokens:
      enabled: true  # Must be true
```

### Verify Database Tables

```sql
-- Check if refresh_tokens table exists
SELECT * FROM information_schema.tables WHERE table_name = 'refresh_tokens';

-- Check table structure
DESCRIBE refresh_tokens;

-- Check for existing tokens
SELECT id, user_id, expires_at, created_at FROM refresh_tokens;
```

### Test the Refresh Endpoint

```bash
# Test refresh token endpoint
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "your-refresh-token"}'
```

## 🚨 Common Issues

### 1. "Refresh token not found" Error

#### Symptoms
```json
{
  "error": "Unauthorized",
  "message": "Refresh token not found",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Causes & Solutions

**❌ Token expired or doesn't exist**
```yaml
# Check expiration configuration
ricardo:
  auth:
    jwt:
      refresh-token-expiration: 2592000000  # 30 days in ms
```

**❌ Database connection issues**
```yaml
# Verify database connection
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/mydb
    username: user
    password: password
```

**❌ Repository type mismatch**
```yaml
# Ensure repository type matches your database
ricardo:
  auth:
    refresh-tokens:
      repository:
        type: "postgresql"  # or "jpa"
```

**✅ Solution:**
```bash
# Check database logs
docker logs your-postgres-container

# Verify token exists in database
SELECT * FROM refresh_tokens WHERE token = 'your-token';
```

### 2. "Invalid or expired refresh token" Error

#### Symptoms
```json
{
  "error": "Unauthorized",
  "message": "Invalid or expired refresh token",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Causes & Solutions

**❌ Token has expired**
```sql
-- Check token expiration
SELECT token, expires_at, 
       CASE WHEN expires_at < NOW() THEN 'EXPIRED' ELSE 'VALID' END as status
FROM refresh_tokens;
```

**❌ Token was rotated**
```yaml
# Check rotation settings
ricardo:
  auth:
    refresh-tokens:
      rotate-on-refresh: true  # Tokens are rotated on each use
```

**✅ Solution:**
- Use the latest refresh token returned from the last `/refresh` call
- Implement proper token storage and rotation in your frontend

### 3. "Too many refresh tokens" Error

#### Symptoms
```json
{
  "error": "Bad Request",
  "message": "Maximum number of refresh tokens exceeded",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Causes & Solutions

**❌ Exceeded token limit per user**
```yaml
# Check token limit
ricardo:
  auth:
    refresh-tokens:
      max-tokens-per-user: 5  # Current limit
```

**✅ Solution:**
```yaml
# Increase limit or implement cleanup
ricardo:
  auth:
    refresh-tokens:
      max-tokens-per-user: 10
      cleanup-interval: 3600000  # 1 hour
```

### 4. PostgreSQL Connection Issues

#### Symptoms
```
org.postgresql.util.PSQLException: Connection to localhost:5432 refused
```

#### Causes & Solutions

**❌ PostgreSQL not running**
```bash
# Start PostgreSQL
sudo systemctl start postgresql
# OR
docker start your-postgres-container
```

**❌ Wrong connection details**
```yaml
# Verify connection settings
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/your_database
    username: your_username
    password: your_password
```

**✅ Solution:**
```bash
# Test connection
psql -h localhost -p 5432 -U your_username -d your_database
```

### 5. JPA Repository Issues

#### Symptoms
```
NoSuchBeanDefinitionException: No qualifying bean of type 'RefreshTokenRepository'
```

#### Causes & Solutions

**❌ Missing JPA dependency**
```xml
<!-- Add to pom.xml -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
```

**❌ Auto-configuration not enabled**
```java
@SpringBootApplication
@EnableJpaRepositories  // Add this annotation
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

**✅ Solution:**
```yaml
# Ensure proper configuration
ricardo:
  auth:
    refresh-tokens:
      repository:
        type: "jpa"
```

### 6. Token Cleanup Issues

#### Symptoms
- Database filling up with expired tokens
- Performance degradation over time

#### Causes & Solutions

**❌ Cleanup not configured**
```yaml
# Enable automatic cleanup
ricardo:
  auth:
    refresh-tokens:
      cleanup-interval: 86400000  # 24 hours
```

**❌ Manual cleanup needed**
```sql
-- Manually clean expired tokens
DELETE FROM refresh_tokens WHERE expires_at < NOW();
```

**✅ Solution:**
```java
// Custom cleanup service
@Scheduled(fixedRate = 3600000) // Every hour
public void cleanupExpiredTokens() {
    refreshTokenRepository.deleteExpiredTokens();
}
```

### 7. Frontend Integration Issues

#### Symptoms
- Tokens not being stored properly
- Infinite refresh loops
- Authentication state not updating

#### Causes & Solutions

**❌ Not handling token rotation**
```javascript
// ❌ Wrong - using old refresh token
const refreshToken = localStorage.getItem('refreshToken');
const response = await fetch('/api/auth/refresh', {
  method: 'POST',
  body: JSON.stringify({ refreshToken })
});

// ✅ Correct - update both tokens
const data = await response.json();
localStorage.setItem('accessToken', data.accessToken);
localStorage.setItem('refreshToken', data.refreshToken);
```

**❌ Not handling refresh failures**
```javascript
// ✅ Proper error handling
try {
  const newTokens = await refreshTokens();
  return newTokens;
} catch (error) {
  // Clear tokens and redirect to login
  localStorage.removeItem('accessToken');
  localStorage.removeItem('refreshToken');
  window.location.href = '/login';
}
```

### 8. CORS Issues with Refresh Endpoint

#### Symptoms
```
Access to fetch at 'http://localhost:8080/api/auth/refresh' from origin 'http://localhost:3000' has been blocked by CORS policy
```

#### Causes & Solutions

**❌ CORS not configured for refresh endpoint**
```java
@CrossOrigin(origins = "http://localhost:3000")
@RestController
public class AuthController {
    // Your endpoints
}
```

**✅ Solution:**
```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins("http://localhost:3000")
            .allowedMethods("GET", "POST", "PUT", "DELETE")
            .allowCredentials(true);
    }
}
```

## 🔧 Debug Configuration

### Enable Debug Logging

```yaml
logging:
  level:
    com.ricardo.auth: DEBUG
    org.springframework.security: DEBUG
    org.springframework.data.jpa: DEBUG
    org.hibernate.SQL: DEBUG
```

### Monitor Token Usage

```java
@Component
public class RefreshTokenDebugger {
    
    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenDebugger.class);
    
    @EventListener
    public void handleTokenRefresh(RefreshTokenEvent event) {
        logger.info("Token refresh attempt for user: {}", event.getUserId());
        logger.info("Token expires at: {}", event.getExpiresAt());
        logger.info("Repository type: {}", event.getRepositoryType());
    }
}
```

### Health Check Endpoint

```java
@RestController
public class HealthController {
    
    private final RefreshTokenRepository refreshTokenRepository;
    
    @GetMapping("/health/refresh-tokens")
    public ResponseEntity<Map<String, Object>> refreshTokenHealth() {
        Map<String, Object> health = new HashMap<>();
        
        try {
            long totalTokens = refreshTokenRepository.count();
            long expiredTokens = refreshTokenRepository.countExpiredTokens();
            
            health.put("totalTokens", totalTokens);
            health.put("expiredTokens", expiredTokens);
            health.put("status", "UP");
            
            return ResponseEntity.ok(health);
        } catch (Exception e) {
            health.put("status", "DOWN");
            health.put("error", e.getMessage());
            return ResponseEntity.status(503).body(health);
        }
    }
}
```

## 🧪 Testing Refresh Token Functionality

### Unit Test

```java
@Test
void shouldRefreshTokenSuccessfully() {
    // Given
    String refreshTokenValue = "test-refresh-token";
    RefreshToken refreshToken = RefreshToken.builder()
        .token(refreshTokenValue)
        .userId(1L)
        .expiresAt(LocalDateTime.now().plusDays(1))
        .build();
    
    when(refreshTokenRepository.findByToken(refreshTokenValue))
        .thenReturn(Optional.of(refreshToken));
    
    // When
    TokenResponse result = refreshTokenService.refreshToken(refreshTokenValue);
    
    // Then
    assertThat(result.getAccessToken()).isNotNull();
    assertThat(result.getRefreshToken()).isNotNull();
}
```

### Integration Test

```java
@SpringBootTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class RefreshTokenIntegrationTest {
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Test
    void shouldRefreshTokenEndToEnd() {
        // Login first
        LoginRequest loginRequest = new LoginRequest("test@example.com", "password");
        ResponseEntity<TokenResponse> loginResponse = restTemplate.postForEntity(
            "/api/auth/login", loginRequest, TokenResponse.class);
        
        // Use refresh token
        String refreshToken = loginResponse.getBody().getRefreshToken();
        RefreshTokenRequest refreshRequest = new RefreshTokenRequest(refreshToken);
        
        ResponseEntity<TokenResponse> refreshResponse = restTemplate.postForEntity(
            "/api/auth/refresh", refreshRequest, TokenResponse.class);
        
        assertThat(refreshResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(refreshResponse.getBody().getAccessToken()).isNotNull();
    }
}
```

## 📊 Performance Monitoring

### Database Queries

```sql
-- Monitor slow queries
SELECT query, calls, mean_time, stddev_time
FROM pg_stat_statements
WHERE query LIKE '%refresh_tokens%'
ORDER BY mean_time DESC;

-- Check index usage
SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes
WHERE tablename = 'refresh_tokens';
```

### Application Metrics

```java
@Component
public class RefreshTokenMetrics {
    
    private final MeterRegistry meterRegistry;
    
    @EventListener
    public void onTokenRefresh(RefreshTokenEvent event) {
        Counter.builder("auth.refresh.attempts")
            .tag("result", event.isSuccess() ? "success" : "failure")
            .register(meterRegistry)
            .increment();
    }
}
```

## 🆘 Getting Help

### Check Configuration

```bash
# Display current configuration
./mvnw spring-boot:run -Dspring-boot.run.arguments=--debug

# Check actuator endpoints
curl http://localhost:8080/actuator/configprops | grep ricardo
```

### Collect Debug Information

```bash
# Application logs
tail -f logs/application.log | grep -i refresh

# Database logs
docker logs your-postgres-container | grep -i error

# JVM metrics
jcmd <pid> GC.run_finalization
```

### Community Support

- 📖 [Documentation](../index.md)
- 🐛 [GitHub Issues](https://github.com/RicardoMorim/Auth-Provider/issues)
- 💬 [Discussions](https://github.com/RicardoMorim/Auth-Provider/discussions)

---

💡 **Still having issues?** Please [open an issue](https://github.com/RicardoMorim/Auth-Provider/issues) with:
- Complete error message
- Configuration files
- Database logs
- Steps to reproduce

### 9. Repository Interface Conflicts

#### Symptoms
```
java.lang.IllegalStateException: Ambiguous mapping. Cannot map 'save' method
```

#### Causes & Solutions

**❌ Multiple save methods in repository hierarchy**
The issue occurs when both `RefreshTokenRepository` and `JpaRepository` define save methods, creating ambiguity.

**✅ Solution:**
The base `RefreshTokenRepository` interface has been redesigned to avoid conflicts:

```java
public interface RefreshTokenRepository {
    RefreshToken saveToken(String token); // in the jpa implementation this will delegate to the save() method 
    Optional<RefreshToken> findByToken(String token);
    void deleteExpiredTokens();
    void revokeAllUserTokens(Long userId);
    long count();
    // ... other methods
}
```

**Custom implementations (PostgreSQL) provide their own save method:**

```java
@Repository
@ConditionalOnProperty(name = "ricardo.auth.refresh-tokens.repository.type", havingValue = "postgresql")
public class PostgreSQLRefreshTokenRepository implements RefreshTokenRepository {
    
    @Override
    public RefreshToken saveToken(RefreshToken token) {
        // Custom PostgreSQL save implementation
        return token;
    }
    
    // ... other methods
}
```

This design ensures:
- ✅ JPA repositories inherit `save()` from `JpaRepository`
- ✅ Custom repositories implement their own `saveToken()` method
- ✅ No method signature conflicts
- ✅ Type-safe repository operations
- ✅ Either way, any usage of the main interface will use the `saveToken()` method, avoiding ambiguity.

### 10. Transaction Management Issues

#### Symptoms
```
org.springframework.dao.InvalidDataAccessApiUsageException: No EntityManager with actual transaction available
```

#### Causes & Solutions

**❌ Missing transaction boundaries**
JPA operations require proper transaction management.

**✅ Solution:**
```java
@Transactional
@Repository
public class JpaRefreshTokenRepository extends JpaRepository<RefreshToken, Long> implements RefreshTokenRepository {
    
    @Transactional
    @Override
    public void deleteExpiredTokens() {
        // Proper transaction boundary
        deleteByExpiresAtBefore(Instant.now());
    }
}
```

**❌ Concurrent access issues**
Multiple threads accessing the same repository can cause conflicts.

**✅ Solution:**
Use proper locking and isolation:

```java
@Lock(LockModeType.PESSIMISTIC_WRITE)
@Query("SELECT r FROM RefreshToken r WHERE r.userId = :userId")
List<RefreshToken> findByUserIdWithLock(@Param("userId") Long userId);
```

### 11. Testing Configuration Issues

#### Symptoms
```
NoSuchBeanDefinitionException: No qualifying bean of type 'TestEntityManager'
```

#### Causes & Solutions

**❌ Missing test configuration**
JPA tests require proper test configuration.

**✅ Solution:**
Use the provided test configuration:

```java
@TestConfiguration
@EnableJpaRepositories(basePackages = "com.ricardo.auth.repository")
@EntityScan(basePackages = "com.ricardo.auth.domain")
public class TestJpaConfiguration {
    
    @Bean
    @Primary
    public RefreshTokenRepository refreshTokenRepository(JpaRefreshTokenRepository jpaRepository) {
        return jpaRepository;
    }
}
```

**❌ Test isolation issues**
Tests may interfere with each other without proper isolation.

**✅ Solution:**
Use proper test annotations:

```java
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(TestJpaConfiguration.class)
@ActiveProfiles("test")
class RefreshTokenRepositoryTest {
    
    @Autowired
    private TestEntityManager entityManager;
    
    @Autowired
    private RefreshTokenRepository repository;
    
    @Test
    @Transactional
    void shouldSaveAndRetrieveToken() {
        // Test implementation
    }
}
```

**❌ Concurrent test failures**
Tests running concurrently may fail due to shared resources.

**✅ Solution:**
Use sequential test execution for integration tests:

```java
@SpringBootTest
@TestMethodOrder(OrderAnnotation.class)
class RefreshTokenIntegrationTest {
    
    @Test
    @Order(1)
    void testTokenCreation() {
        // Test 1
    }
    
    @Test
    @Order(2)
    void testTokenRefresh() {
        // Test 2
    }
}
```
