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
  mail:
    host: "smtp.gmail.com"
    port: 587
    username: ${MAIL_USERNAME:your_smtp_username}
    password: ${MAIL_PASSWORD:your_smtp_password}
    properties:
      mail:
        smtp:
          auth: true
          starttls:
            enable: true

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
      type: MEMORY # or REDIS
    rate-limiter:
      enabled: true
      type: MEMORY # or REDIS
      max-requests: 150
      time-window-ms: 60000
    # Secure cookies for tokens (REQUIRED)
    cookies:
      access:
        secure: true
        http-only: true
        same-site: STRICT
        path: "/"
      refresh:
        secure: true
        http-only: true
        same-site: STRICT
        path: "/api/auth/refresh"
    # Force HTTPS in production (REQUIRED for cookies)
    redirect-https: true
    # Email configuration for password reset
    email:
      from-address: "noreply@yourdomain.com"
      from-name: "Your App Name"
      host: "smtp.gmail.com"
      port: 587
      reset-subject: "Password Reset Request"
      reset-template: "default"
    # Password reset configuration
    password-reset:
      enabled: true
      token-expiry-hours: 1   # 1 hour
      max-attempts: 3
      enable-cleanup: true
      cleanup-interval-hours: 24
    # Redis config (if using REDIS for blocklist/rate-limiter)
    redis:
      host: "localhost"
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

## 🚨 What's New in v4.0.0

**New Features in v4.0.0:**
- **Password Reset System**: OWASP-compliant password reset with email integration
- **Role Management API**: Full CRUD API for role management with proper authorization
- **OpenAPI Integration**: Complete Swagger/OpenAPI documentation at `/swagger-ui.html`
- **Enhanced Input Sanitization**: Advanced input validation and sanitization
- **Better Exception Handling**: Improved error responses and exception management
- **Domain Events**: Comprehensive audit trail with event publishing

**Previous Major Changes (Still Required):**
- **Cookie Authentication (v2.0.0)**: Authentication uses secure HTTP-only cookies exclusively
- **HTTPS Required (v2.0.0)**: Secure cookies require HTTPS in production environments
- **UUID Primary Keys (v3.0.0)**: All entities use UUID instead of Long for IDs
- **CSRF Protection (v3.0.0)**: Enhanced security with CSRF tokens

### Migration to v4.0.0

**New Configuration Required:**
- Configure email settings for password reset functionality
- Update any custom role management code to use new API
- Access interactive API documentation at `/swagger-ui.html`

**Email Configuration (New in v4.0.0):**
```yaml
ricardo:
  auth:
    email:
      from-address: "noreply@yourdomain.com"
      from-name: "Your App Name"
      host: "smtp.gmail.com"
      port: 587
    password-reset:
      enabled: true
      token-expiry-hours: 1
      max-attempts: 3

spring:
  mail:
    host: "smtp.gmail.com"
    port: 587
    username: ${MAIL_USERNAME:your_username}
    password: ${MAIL_PASSWORD:your_password}
    properties:
      mail:
        smtp:
          auth: true
          starttls:
            enable: true
```

## 📚 Documentation & Next Steps

### For Development

- **[Examples](docs/examples.md)** - See complete project examples
- **[API Reference](docs/api-reference.md)** - Explore all endpoints
- **[Configuration Guide](docs/configuration.md)** - Customize settings
- **[OpenAPI Documentation](http://localhost:8080/swagger-ui.html)** - Interactive API testing (NEW in v4.0.0)

### Authentication Architecture (Established in v2.0.0)

- **Cookie-only authentication**: All authentication uses secure HTTP-only cookies exclusively
- **No Authorization headers**: Authorization header authentication removed for security
- **HTTPS required**: Production environments require HTTPS for secure cookie operation
- **Rate limiting & token blocklist**: Built-in protection against abuse (v2.0.0)
- **CSRF protection**: Enhanced security with CSRF tokens (v3.0.0)

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
