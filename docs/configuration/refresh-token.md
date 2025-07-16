# Refresh Token Configuration

Complete guide to configuring refresh tokens for secure, long-lived user sessions.

## 🔄 Overview

Refresh tokens provide a secure way to maintain user sessions without requiring frequent re-authentication. The Ricardo Auth starter includes a comprehensive refresh token system with:

- **Secure token generation** with unique identifiers
- **Configurable storage backends** (JPA and PostgreSQL)
- **Automatic token rotation** for enhanced security
- **Expiration management** with configurable timeouts
- **Performance optimizations** for high-traffic applications

## ⚙️ Basic Configuration

### Enable Refresh Tokens

```yaml
ricardo:
  auth:
    refresh-tokens:
      enabled: true                    # Enable refresh token functionality
      repository:
        type: "jpa"                    # Storage backend: "jpa" or "postgresql"
    jwt:
      refresh-token-expiration: 604800000  # 7 days in milliseconds
```

### Complete Example

```yaml
ricardo:
  auth:
    jwt:
      secret: "your-256-bit-secret-key"
      access-token-expiration: 900000     # 15 minutes for access tokens
      refresh-token-expiration: 604800000 # 7 days for refresh tokens
    refresh-tokens:
      enabled: true
      max-tokens-per-user: 5
      rotate-on-refresh: true
      cleanup-interval: 3600000
      auto-cleanup: true
      repository:
        type: "jpa"
```

## 🗄️ Storage Options

### JPA Storage (Default)

Uses Spring Data JPA with your configured database:

```yaml
ricardo:
  auth:
    refresh-tokens:
      repository:
        type: "jpa"
```

**Advantages:**
- ✅ Works with any JPA-compatible database
- ✅ Automatic schema creation
- ✅ Simple configuration
- ✅ Transaction support

**Best for:** Small to medium applications, development environments

### PostgreSQL Storage

Optimized PostgreSQL implementation with native queries:

```yaml
ricardo:
  auth:
    refresh-tokens:
      repository:
        type: "postgresql"
```

**Advantages:**
- ✅ High performance with native queries
- ✅ Optimized for PostgreSQL features
- ✅ Better concurrency handling
- ✅ Advanced indexing support

**Best for:** Production environments, high-traffic applications

## 🔧 Configuration Properties

### Complete Reference

```yaml
ricardo:
  auth:
    jwt:
      access-token-expiration: 900000     # Access token expiration (15 minutes)
      refresh-token-expiration: 604800000 # Refresh token expiration (7 days)
    refresh-tokens:
      enabled: true                       # Enable/disable refresh tokens
      max-tokens-per-user: 5              # Maximum tokens per user
      rotate-on-refresh: true             # Rotate tokens on each refresh
      cleanup-interval: 3600000           # Cleanup interval (1 hour)
      auto-cleanup: true                  # Enable automatic cleanup
      repository:
        type: "jpa"                       # Storage backend: "jpa" or "postgresql"
        database:
          refresh-tokens-table: "refresh_tokens"  # Table name
          schema: ""                      # Database schema (optional)
```

### Property Details

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `refresh-tokens.enabled` | Boolean | `true` | Enable/disable refresh token functionality |
| `refresh-tokens.repository.type` | String | `"jpa"` | Storage backend (`"jpa"` or `"postgresql"`) |
| `jwt.refresh-token-expiration` | Long | `604800000` | Token expiration time in milliseconds (7 days) |
| `refresh-tokens.cleanup-interval` | Long | `3600000` | Cleanup interval for expired tokens (1 hour) |
| `refresh-tokens.max-tokens-per-user` | Integer | `5` | Maximum active tokens per user |
| `refresh-tokens.rotate-on-refresh` | Boolean | `true` | Rotate tokens on each refresh |
| `refresh-tokens.auto-cleanup` | Boolean | `true` | Enable automatic token cleanup |
| `refresh-tokens.repository.database.refresh-tokens-table` | String | `"refresh_tokens"` | Database table name |
| `refresh-tokens.repository.database.schema` | String | `""` | Database schema (optional) |

## 🏗️ Repository Implementation Details

### Interface Design

The refresh token system uses a carefully designed interface hierarchy to avoid conflicts:

```java
// Base interface - save method is `saveToken()` to avoid conflicts
public interface RefreshTokenRepository {
    RefreshToken saveToken(RefreshToken token); 
    Optional<RefreshToken> findByToken(String token);
    void deleteExpiredTokens();
    void revokeAllUserTokens(Long userId);
    long count();
    // ... other methods
}

// JPA implementation - inherits save from JpaRepository
public interface JpaRefreshTokenRepository extends RefreshTokenRepository, JpaRepository<RefreshToken, Long> {
    @Override
    default RefreshToken saveToken(RefreshToken token) {
        return save(token); // Delegates to JpaRepository's save method
    }
    @Query("DELETE FROM RefreshToken r WHERE r.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") Instant now);
}

// Custom PostgreSQL implementation - provides its own save method
@Repository
public class PostgreSQLRefreshTokenRepository implements RefreshTokenRepository {
    
    public RefreshToken saveToken(RefreshToken token) {
        // Custom PostgreSQL save implementation
        return token;
    }
    
    // ... other methods
}
```

This design ensures:
- ✅ No method signature conflicts
- ✅ Type-safe operations
- ✅ Proper inheritance hierarchy
- ✅ Backend-specific optimizations

### JPA Storage

The system automatically creates the required table with optimized indexes:

```sql
CREATE TABLE refresh_tokens (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    token VARCHAR(255) UNIQUE NOT NULL,
    user_id BIGINT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
```

### PostgreSQL Storage

For PostgreSQL, additional optimizations are applied:

```sql
CREATE TABLE refresh_tokens (
    id BIGSERIAL PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    user_id BIGINT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX CONCURRENTLY idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX CONCURRENTLY idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX CONCURRENTLY idx_refresh_tokens_token ON refresh_tokens(token);
```

### PostgreSQL Timestamp Handling

The PostgreSQL implementation includes proper timestamp conversion for optimal performance:

```java
// Automatic conversion from Instant to Timestamp
public RefreshToken save(RefreshToken token) {
    if (token.getId() == null) {
        return insert(token);
    } else {
        return update(token);
    }
}

private RefreshToken insert(RefreshToken token) {
    // Properly converts Instant to Timestamp for PostgreSQL
    Timestamp expiresAt = Timestamp.from(token.getExpiresAt());
    Timestamp createdAt = Timestamp.from(token.getCreatedAt());
    
    // Native PostgreSQL INSERT with RETURNING clause
    String sql = """
        INSERT INTO refresh_tokens (token, user_id, expires_at, created_at)
        VALUES (?, ?, ?, ?)
        RETURNING id
        """;
    
    // ... implementation
}
```

This ensures:
- ✅ Proper timestamp precision handling
- ✅ Timezone-aware operations
- ✅ Optimal PostgreSQL performance
- ✅ Consistent data types

## 📱 Usage Examples

### Login Flow

```bash
# 1. User logs in
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'

# Response:
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Token Refresh Flow

```bash
# 2. Access token expires, use refresh token
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'

# Response:
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Frontend Integration

```javascript
// Store tokens securely
localStorage.setItem('accessToken', response.accessToken);
localStorage.setItem('refreshToken', response.refreshToken);

// Automatic token refresh
async function apiCall(url, options = {}) {
  const accessToken = localStorage.getItem('accessToken');
  
  const response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${accessToken}`
    }
  });
  
  if (response.status === 401) {
    // Token expired, refresh it
    const refreshToken = localStorage.getItem('refreshToken');
    const refreshResponse = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken })
    });
    
    if (refreshResponse.ok) {
      const tokens = await refreshResponse.json();
      localStorage.setItem('accessToken', tokens.accessToken);
      localStorage.setItem('refreshToken', tokens.refreshToken);
      
      // Retry original request
      return fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${tokens.accessToken}`
        }
      });
    }
  }
  
  return response;
}
```

## 🔒 Security Considerations

### Token Rotation

The system automatically rotates refresh tokens on each use:

```yaml
ricardo:
  auth:
    refresh-tokens:
      rotate-on-refresh: true    # Always rotate tokens (recommended)
```

### Token Limits

Prevent token accumulation with user limits:

```yaml
ricardo:
  auth:
    refresh-tokens:
      max-tokens-per-user: 5  # Maximum 5 active tokens per user
```

### Cleanup Strategy

Expired tokens are automatically cleaned up:

```yaml
ricardo:
  auth:
    refresh-tokens:
      cleanup-interval: 86400000  # Clean up every 24 hours
```

## 🚀 Performance Optimization

### Connection Pooling

For high-traffic applications, configure connection pooling:

```yaml
spring:
  datasource:
    hikari:
      maximum-pool-size: 20
      minimum-idle: 5
      connection-timeout: 30000
      idle-timeout: 600000
```

### Caching

Enable caching for frequently accessed tokens:

```yaml
spring:
  cache:
    type: redis
    redis:
      time-to-live: 3600000  # 1 hour
```

### Monitoring

Monitor token usage and performance:

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,metrics,info
  metrics:
    export:
      prometheus:
        enabled: true
```

## 🔧 Advanced Configuration

### Custom Token Generator

Implement custom token generation logic:

```java
@Component
@Primary
public class CustomRefreshTokenGenerator implements RefreshTokenGenerator {
    
    @Override
    public String generateToken(User user) {
        // Custom token generation logic
        return UUID.randomUUID().toString() + "-" + user.getId();
    }
}
```

### Custom Repository

Create a custom repository implementation:

```java
@Repository
@ConditionalOnProperty(name = "ricardo.auth.refresh-token.repository-type", havingValue = "custom")
public class CustomRefreshTokenRepository implements RefreshTokenRepository {
    
    @Override
    public void save(RefreshToken token) {
        // Custom save logic
    }
    
    @Override
    public Optional<RefreshToken> findByToken(String token) {
        // Custom find logic
        return Optional.empty();
    }
    
    // ... other methods
}
```

## 🐛 Troubleshooting

### Common Issues

#### 1. "RefreshToken not found"
**Cause:** Token expired or doesn't exist
**Solution:** Check token expiration and storage configuration

#### 2. "Too many refresh tokens"
**Cause:** Exceeded `max-tokens-per-user` limit
**Solution:** Increase limit or implement token cleanup

#### 3. "Database connection issues"
**Cause:** Database not configured or connection pool exhausted
**Solution:** Verify database configuration and connection pooling

### Debug Configuration

Enable debug logging for refresh token operations:

```yaml
logging:
  level:
    com.ricardo.auth.refresh: DEBUG
    org.springframework.security: DEBUG
```

## 📚 Related Documentation

- [API Reference](../api-reference.md#refresh-endpoints)
- [Security Guide](../security-guide.md#token-security)
- [Database Configuration](database.md)
- [Performance Optimization](../examples/performance.md)

## 🎯 Best Practices

1. **Use short-lived access tokens** (1-15 minutes) with long-lived refresh tokens (days/weeks)
2. **Always rotate refresh tokens** on use for enhanced security
3. **Implement token cleanup** to prevent database bloat
4. **Use PostgreSQL storage** for high-performance applications
5. **Monitor token usage** and set appropriate limits
6. **Store tokens securely** on the client side (httpOnly cookies preferred)
7. **Implement proper error handling** for token refresh failures

---

💡 **Need help?** Check the [troubleshooting guide](../troubleshooting/) or [open an issue](https://github.com/RicardoMorim/Auth-Provider/issues).
