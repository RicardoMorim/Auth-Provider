# Configuration Properties Quick Reference

## 🚀 Essential Properties

### Minimum Required Configuration

```yaml
ricardo:
  auth:
    jwt:
      secret: "your-256-bit-base64-encoded-secret-key-here"  # REQUIRED
```

### Development Configuration

```yaml
ricardo:
  auth:
    jwt:
      secret: "ZGV2ZWxvcG1lbnQtc2VjcmV0LWtleS1hdXRoLXN0YXJ0ZXI="  # Base64: "development-secret-key-auth-starter"
    cookies:
      access:
        secure: false     # Allow HTTP for localhost
      refresh:
        secure: false
    redirect-https: false   # Disable HTTPS redirect for development
```

### Production Configuration

```yaml
ricardo:
  auth:
    jwt:
      secret: "${JWT_SECRET}"                    # Environment variable
      access-token-expiration: 900000           # 15 minutes
      refresh-token-expiration: 604800000       # 7 days
    cookies:
      access:
        secure: true      # HTTPS only
        same-site: Strict # Maximum CSRF protection
      refresh:
        secure: true
        same-site: Strict
    redirect-https: true  # Force HTTPS
    rate-limiter:
      enabled: true
      type: redis         # Use Redis for clustering
      max-requests: 100   # Stricter limits
    token-blocklist:
      type: redis         # Shared token revocation
```

---

## 📋 Complete Properties Reference

### Core Authentication Properties

```yaml
ricardo:
  auth:
    enabled: true                    # Master enable/disable switch
    redirect-https: true            # Force HTTPS redirect
    
    jwt:
      secret: ""                    # REQUIRED - Base64 encoded secret key
      access-token-expiration: 900000    # 15 minutes (in milliseconds)
      refresh-token-expiration: 604800000  # 7 days (in milliseconds)
```

### Controller Configuration

```yaml
ricardo:
  auth:
    controllers:
      auth:
        enabled: true               # Enable /api/auth/* endpoints
      user:
        enabled: true               # Enable /api/users/* endpoints
```

### Cookie Security

```yaml
ricardo:
  auth:
    cookies:
      access:
        secure: true                # HTTPS-only (auto-detected)
        http-only: true             # Prevent JavaScript access
        same-site: STRICT           # CSRF protection (STRICT/LAX/NONE)
        path: "/"                   # Cookie path
      refresh:
        secure: true
        http-only: true
        same-site: STRICT
        path: "/api/auth/refresh"   # Restricted to refresh endpoint
```

### Password Policy

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 8                                   # Minimum password length
      max-length: 128                                 # Maximum password length
      require-uppercase: true                         # Require uppercase letters
      require-lowercase: true                         # Require lowercase letters
      require-digits: true                            # Require numeric digits
      require-special-chars: false                    # Require special characters
      allowed-special-chars: "!@#$%^&*()_+-=[]{}|;:,.<>?"  # Allowed special characters
      prevent-common-passwords: true                  # Block common passwords
      common-passwords-file-path: "/commonpasswords.txt"   # Common passwords file
```

### Refresh Token Management

```yaml
ricardo:
  auth:
    refresh-tokens:
      enabled: true                 # Enable refresh token functionality
      max-tokens-per-user: 5       # Maximum tokens per user (0 = unlimited)
      rotate-on-refresh: true      # Generate new token on refresh
      auto-cleanup: true           # Automatic expired token cleanup
      cleanup-interval: 3600000    # Cleanup interval (1 hour in ms)
```

### Rate Limiting

```yaml
ricardo:
  auth:
    rate-limiter:
      enabled: true                # Enable rate limiting
      type: MEMORY                # MEMORY or REDIS
      max-requests: 150           # Maximum requests per time window
      time-window-ms: 60000       # Time window (1 minute in ms)
```

### Token Blocklist (Revocation)

```yaml
ricardo:
  auth:
    token-blocklist:
      enabled: true               # Enable token revocation
      type: MEMORY               # MEMORY or REDIS
```

### Repository Configuration

```yaml
ricardo:
  auth:
    repository:
      type: JPA                   # JPA (default) or POSTGRESQL
      database:
        refresh-tokens-table: "refresh_tokens"
        password-reset-tokens-table: "password_reset_tokens"
        schema: "public"          # Database schema (PostgreSQL only)
```

### Redis Configuration

```yaml
ricardo:
  auth:
    redis:
      host: localhost             # Redis server host
      port: 6379                 # Redis server port
      password: ""               # Redis password (optional)
      database: 0                # Redis database number
```

### Password Reset

```yaml
ricardo:
  auth:
    password-reset:
      enabled: true                          # Enable password reset
      token-expiry-hours: 1                  # Reset token expiration
      max-attempts: 3                        # Max attempts per email
      time-window-ms: 3600000               # Time window for attempts
      enable-cleanup: true                   # Auto-cleanup expired tokens
      cleanup-interval-hours: 24             # Cleanup interval
      token-length: 32                       # Reset token length
      require-https: true                    # HTTPS required for reset links
```

### Email Configuration

```yaml
ricardo:
  auth:
    email:
      from-address: "noreply@example.com"    # Sender email address
      password: ""                           # Email password (use MAIL_PASSWORD env var)
      host: "smtp.gmail.com"                 # SMTP host
      port: 587                              # SMTP port
      from-name: "Auth Service"              # Sender display name
      reset-subject: "Password Reset Request" # Reset email subject
      reset-template: "default"              # Email template name
```

## 🔧 Environment-Specific Examples

### application-dev.yml

```yaml
ricardo:
  auth:
    jwt:
      secret: "ZGV2ZWxvcG1lbnQtc2VjcmV0LWtleS1hdXRoLXN0YXJ0ZXI="
      access-token-expiration: 1800000  # 30 minutes for development
    cookies:
      access:
        secure: false
      refresh:
        secure: false
    redirect-https: false
    rate-limiter:
      max-requests: 1000  # Higher limits for development

logging:
  level:
    com.ricardo.auth: DEBUG
    org.springframework.security: DEBUG
```

### application-prod.yml

```yaml
ricardo:
  auth:
    jwt:
      secret: "${JWT_SECRET}"
      access-token-expiration: 900000   # 15 minutes
      refresh-token-expiration: 604800000  # 7 days
    cookies:
      access:
        secure: true
        same-site: Strict
      refresh:
        secure: true
        same-site: Strict
    redirect-https: true
    rate-limiter:
      enabled: true
      type: redis
      max-requests: 100
    token-blocklist:
      type: redis
    repository:
      type: POSTGRESQL

spring:
  datasource:
    url: "${DATABASE_URL}"
    username: "${DATABASE_USERNAME}"
    password: "${DATABASE_PASSWORD}"
```

### application-test.yml

```yaml
ricardo:
  auth:
    jwt:
      secret: "dGVzdC1zZWNyZXQta2V5LWF1dGgtc3RhcnRlci10ZXN0aW5n"
      access-token-expiration: 300000   # 5 minutes for tests
    cookies:
      access:
        secure: false
      refresh:
        secure: false
    redirect-https: false
    rate-limiter:
      enabled: false  # Disable for testing
    token-blocklist:
      type: memory

spring:
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
  jpa:
    hibernate:
      ddl-auto: create-drop
```

---

## 🔒 Security Best Practices

### Production Secrets

```yaml
# ❌ Never store secrets in code
ricardo:
  auth:
    jwt:
      secret: "hardcoded-secret"

# ✅ Use environment variables
ricardo:
  auth:
    jwt:
      secret: "${JWT_SECRET}"

# ✅ Or external configuration
ricardo:
  auth:
    jwt:
      secret: "${spring.cloud.config.uri}/jwt-secret"
```

### HTTPS Configuration

```yaml
# Force HTTPS in production
server:
  port: 8443
  ssl:
    enabled: true
    key-store: classpath:keystore.p12
    key-store-password: ${SSL_PASSWORD}
    key-store-type: PKCS12
    key-alias: tomcat

ricardo:
  auth:
    redirect-https: true
    cookies:
      access:
        secure: true
      refresh:
        secure: true
```

### Database Security

```yaml
# Use connection pooling and SSL
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/authdb?sslmode=require
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
    hikari:
      maximum-pool-size: 10
      minimum-idle: 5
      connection-timeout: 20000
```

---

## 📖 Related Documentation

- [Developer Bean Documentation](developer-bean-documentation.md)
- [Security Guide](security-guide.md)
- [Cookie Authentication Guide](cookie-authentication-guide.md)
- [Configuration Examples](configuration/index.md)
