# Getting Started with Ricardo Auth

Welcome! This guide will have you up and running with Ricardo Auth in **5 minutes**.

## 🚀 What is Ricardo Auth?

Ricardo Auth is a **plug-and-play Spring Boot starter** that adds JWT authentication and user management to your
application with zero configuration required.

**Perfect for:**

- New Spring Boot projects that need authentication
- Existing apps wanting to add user management quickly
- Developers who want secure defaults without the complexity

## ⚡ 5-Minute Setup

### Step 1: Add Dependency (30 seconds)

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.ricardomorim</groupId>
    <artifactId>auth-spring-boot-starter</artifactId>
    <version>4.0.0</version>
</dependency>

<!-- Required: Database support -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
<dependency>
    <groupId>com.h2database</groupId>
    <artifactId>h2</artifactId>
    <scope>runtime</scope>
</dependency>
```

### Step 2: Configure (1 minute)

Add to your `application.yml`:

```yaml
# Database (H2 for quick start)
spring:
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
    username: sa
    password: password
  jpa:
    hibernate:
      ddl-auto: create-drop

# Required: JWT Secret
ricardo:
  auth:
    jwt:
      secret: "your-super-secure-secret-key-make-it-long-256-bits-for-security"
      access-token-expiration: 900000     # 15 minutes for access tokens
      refresh-token-expiration: 604800000 # 7 days for refresh tokens
    refresh-tokens:
      enabled: true        # Enable refresh tokens
      max-tokens-per-user: 5
      auto-cleanup: true
    # Enable blocklist and rate limiting (recommended)
    token-blocklist:
      enabled: true
      type: memory # or redis
    rate-limiter:
      enabled: true
      type: memory # or redis
      max-requests: 100
      time-window-ms: 60000
    # Secure cookies for tokens (REQUIRED)
    cookies:
      access:
        secure: true
        http-only: true
        same-site: Strict
        path: /
      refresh:
        secure: true
        http-only: true
        same-site: Strict
        path: /api/auth/refresh
    # Force HTTPS in production (REQUIRED for cookies)
    redirect-https: true
    # CORS configuration (REQUIRED for frontend apps)
    cors:
      allowed-origins: ["http://localhost:3000", "https://yourdomain.com"]
      allowed-methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
      allowed-headers: ["*"]
      allow-credentials: true
      max-age: 3600
    # Email configuration for password reset
    email:
      enabled: true
      from: "noreply@yourdomain.com"
      reset-url-template: "https://yourdomain.com/reset-password?token={token}"
    # Password reset configuration
    password-reset:
      enabled: true
      token-expiration: 3600000 # 1 hour
      max-attempts: 3
      cleanup-interval: 3600000
    # Redis config (if using redis for blocklist/rate-limiter)
    redis:
      host: localhost
      port: 6379
      password: ""
      database: 0
```

### Step 3: Start Application (1 minute)

```java
@SpringBootApplication
public class MyApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}
```

Run: `mvn spring-boot:run`

### Step 4: Test API (2 minutes)

**Create your first user:**

```bash
curl -X POST http://localhost:8080/api/users/create \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john",
    "email": "john@example.com",
    "password": "SecurePass@123!"
  }'
```

**Login to get JWT tokens (now set as secure cookies):**

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass@123!"
  }'
# Tokens are now automatically set as secure HTTP-only cookies
```

**Refresh your access token (automatic cookie handling):**

```bash
curl -X POST http://localhost:8080/api/auth/refresh \
  --cookie "refresh_token=YOUR_REFRESH_TOKEN_HERE" \
  -H "Content-Type: application/json"
# New tokens are automatically set as cookies
```

**Use the access token (automatic cookie authentication):**

```bash
curl --cookie "access_token=YOUR_ACCESS_TOKEN_HERE" \
     http://localhost:8080/api/auth/me
```

**Test password reset functionality:**

```bash
# Request password reset
curl -X POST http://localhost:8080/api/auth/password-reset/request \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com"
  }'

# Confirm password reset (with token from email)
curl -X POST http://localhost:8080/api/auth/password-reset/confirm \
  -H "Content-Type: application/json" \
  -d '{
    "token": "reset-token-from-email",
    "newPassword": "NewSecurePass@456!"
  }'
```

**View OpenAPI documentation:**

Visit `http://localhost:8080/swagger-ui.html` for interactive API documentation.

🎉 **Congratulations!** You now have a Spring Boot app with:

- ✅ User registration and login
- ✅ JWT access and refresh tokens via secure HTTP-only cookies
- ✅ Secure token refresh system with automatic rotation
- ✅ OWASP-compliant password reset with email integration
- ✅ Strong password policies with validation
- ✅ Role-based access control with role management API
- ✅ Complete CORS configuration for frontend integration
- ✅ Comprehensive OpenAPI/Swagger documentation
- ✅ Domain events for audit logging
- ✅ Rate limiting and token blocklist for security
- ✅ Complete REST API with interactive documentation

## 🚨 Breaking Changes in v4.0.0

**Cookie-Only Authentication System**
- **BREAKING**: Authentication now exclusively uses secure HTTP-only cookies
- **No More Bearer Tokens**: Authorization header authentication completely removed
- **HTTPS Required**: Secure cookies require HTTPS in production environments
- **CORS Required**: Frontend applications must configure CORS with credentials

**New Security Features**
- **Enhanced CORS**: Comprehensive CORS configuration with credentials support
- **Password Reset**: OWASP-compliant password reset with email integration
- **Role Management**: Full CRUD API for role management with proper authorization
- **OpenAPI Integration**: Complete Swagger/OpenAPI documentation
- **Domain Events**: Comprehensive audit trail with event publishing

### Migration from v3.x to v4.0.0

**⚠️ Critical**: This is a major version with breaking authentication changes.

**Key Changes:**
- Remove all `Authorization: Bearer` headers from frontend code
- Add CORS configuration for your frontend domains
- Ensure HTTPS is configured for production
- Update API calls to use `credentials: 'include'` for automatic cookie handling
- Configure email settings for password reset functionality

**Frontend Update Required:**
```javascript
// OLD (3.x): Manual Authorization headers
fetch('/api/auth/me', {
  headers: { 'Authorization': `Bearer ${token}` }
});

// NEW (4.0): Automatic cookie handling
fetch('/api/auth/me', {
  credentials: 'include' // Ensures cookies are sent automatically
});
```

## 🚨 Breaking Changes & Security Notes

- **Cookie-only authentication**: All authentication now uses secure HTTP-only cookies exclusively
- **No Authorization headers**: Authorization header authentication has been completely removed
- **HTTPS required**: Production environments require HTTPS for secure cookie operation
- **CORS configuration required**: Frontend applications must configure CORS with credentials support
- **Email integration**: Password reset requires email configuration
- **Enhanced security**: Rate limiting, CSRF protection, and input validation enabled by default

## 🎯 What's Next?

### For Development

- **[Examples](docs/examples.md)** - See complete project examples
- **[API Reference](docs/api-reference.md)** - Explore all endpoints
- **[Configuration Guide](docs/configuration.md)** - Customize settings

### For Production

- **[Security Guide](docs/security-guide.md)** - Production security setup
- **[Environment Variables](docs/configuration-guide.md#environment-variables)** - Secure configuration
- **[Troubleshooting](docs/troubleshooting.md)** - Common issues and fixes

## 🆘 Need Help?

**Common Issues:**

- **"JWT secret not configured"** → Add `ricardo.auth.jwt.secret` to your config
- **"Failed to configure DataSource"** → Add `spring-boot-starter-data-jpa` dependency
- **"Password doesn't meet requirements"** → Use pattern: `Uppercase + lowercase + digit + symbol` (e.g., `MyPass123!`)
- **"No access token cookie found"** → Ensure your frontend sends cookies with requests and CORS is configured
- **"CORS error"** → Add your frontend domain to `ricardo.auth.cors.allowed-origins`
- **"Token revoked"** → Token was revoked via blocklist (logout or admin action)
- **429 Too Many Requests** → Rate limiting is enabled, wait and try again
- **"Email not configured"** → Add email configuration for password reset functionality
- **"HTTPS required"** → Configure SSL/TLS for production or disable with `redirect-https: false` for development

**Get Support:**

- 📖 [Documentation](docs/index.md) - Complete guides
- 🐛 [GitHub Issues](https://github.com/RicardoMorim/Auth-Provider/issues) - Report problems
- 💬 [Discussions](https://github.com/RicardoMorim/Auth-Provider/discussions) - Ask questions

---

⭐ **Found this helpful?** Give us a star on [GitHub](https://github.com/RicardoMorim/Auth-Provider)!
