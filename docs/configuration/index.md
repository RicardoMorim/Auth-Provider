# Configuration Overview

> **Breaking Change (v2.0.0):**
> - Authentication now uses secure cookies (`access_token`, `refresh_token`) with `HttpOnly`, `Secure`, and `SameSite`
    flags by default. You must use HTTPS in production or set `ricardo.auth.cookies.access.secure: false` for local
    development only.
> - New blocklist and rate limiting features are available (see below).
> - New `/api/auth/revoke` admin endpoint for revoking tokens (access or refresh).

Complete guide to configuring Ricardo Auth for your specific needs.

## 🚀 Quick Setup (2 minutes)

**Minimum required configuration to get started:**

> **Note:** The legacy `expiration` property is deprecated. Use `access-token-expiration` and `refresh-token-expiration`
> for all new configurations.

```yaml
ricardo:
  auth:
    jwt:
      secret: "your-256-bit-secret-key-here-make-it-long-and-secure"
      access-token-expiration: 86400000
      refresh-token-expiration: 604800000
    # NEW in v3.0.0: CSRF protection is enabled by default
    # No additional configuration needed - works out of the box
    # Public endpoints (/api/auth/login, /api/users/create) are automatically exempt
    # --- Blocklist and Rate Limiter ---
    token-blocklist:
      enabled: true
      type: memory   # or 'redis' for distributed blocklist
    rate-limiter:
      enabled: true
      type: memory   # or 'redis' for distributed rate limiting
      max-requests: 100
      time-window-ms: 60000
    # --- Cookie Security ---
    cookies:
      access:
        secure: true      # Set to false for local dev only
        http-only: true
        same-site: Strict # Strict/Lax/None
        path: /
      refresh:
        secure: true
        http-only: true
        same-site: Strict
        path: /api/auth/refresh
    redirect-https: true   # Enforce HTTPS (recommended for production)```

  That's it! Ricardo Auth will use sensible defaults for everything else.

## 📋 Configuration Checklist

### ✅ **Required (Must Have)**
- [ ] [ JWT secret key configured ](basic.md#jwt-configuration) - `ricardo.auth.jwt.secret`
- [ ] [ Database dependency added ](basic.md#database-setup) - `spring-boot-starter-data-jpa`
- [ ] [ Database configured ](database.md) - Connection details in `application.yml`

### 🎯 **Recommended for Production**
- [ ] [ Environment variables for secrets ](environment.md) - Don't hardcode secrets
- [ ] [ Password policy configured ](password-policy.md) - Strengthen password requirements
- [ ] [ Database connection pooling ](database.md#connection-pooling) - Performance optimization
- [ ] [ Security configuration ](security.md) - HTTPS, CORS, headers
- [ ] [ Logging levels ](basic.md#logging-configuration) - Appropriate for environment

### ⚙️ **Optional Customizations**
- [ ] [ Custom token expiration ](basic.md#jwt-configuration) - Adjust for your use case
- [ ] [ Disabled endpoints ](basic.md#endpoint-configuration) - Turn off unused features
- [ ] [ Custom security rules ](security.md#custom-security) - Advanced security needs
- [ ] [ Advanced features ](advanced.md) - Rate limiting, caching, etc.

## 📚 Configuration Guides

### **Getting Started**
  | Guide | Purpose | Time | When to Use |
  |-------|---------|------|-------------|
  | **[Basic Configuration](basic.md)** | Essential setup options | 5 min | First time setup |
  | **[Database Configuration](database.md)** | Database connection and settings | 10 min | Setting up persistence |

### **Security & Policies** 
  | Guide | Purpose | Time | When to Use |
  |-------|---------|------|-------------|
  | **[Password Policy](password-policy.md)** 🆕 | Password strength requirements | 10 min | Enhancing security |
  | **[Refresh Token Configuration](refresh-token.md)** 🆕 | Token refresh and storage | 15 min | Session management |
  | **[Security Configuration](security.md)** | Production security settings | 15 min | Production deployment |

### **Production Ready**
  | Guide | Purpose | Time | When to Use |
  |-------|---------|------|-------------|
  | **[Environment Variables](environment.md)** | Secure configuration management | 10 min | Multiple environments |
  | **[Advanced Configuration](advanced.md)** | Performance and customization | 20 min | Complex requirements |

## 🎯 Configuration by Use Case

### **Development Environment**
Quick setup for local development:
  ```yaml
ricardo:
  auth:
    jwt:
      secret: "dev-secret-key-256-bits-long-for-development-use-only"
      access-token-expiration: 86400000  # 1 day
      refresh-token-expiration: 604800000 # 7 days
    password-policy:
      min-length: 6         # Relaxed for testing
      require-special-chars: false
    # --- NEW: Blocklist and Rate Limiter ---
    token-blocklist:
      enabled: true
      type: memory   # or 'redis' for distributed blocklist
    rate-limiter:
      enabled: true
      type: memory   # or 'redis' for distributed rate limiting
      max-requests: 100
      time-window-ms: 60000
    # --- NEW: Cookie Security ---
    cookies:
      access:
        secure: false      # Set to true in production
        http-only: true
        same-site: Lax
        path: /
      refresh:
        secure: false
        http-only: true
        same-site: Lax
        path: /api/auth/refresh
  redirect-https: false   # Disable HTTPS redirect for development
```

👉 **See:** [Basic Configuration](basic.md#development-setup)

### **Production Environment**

Secure setup for production:

```yaml
ricardo:
  auth:
    jwt:
      secret: ${JWT_SECRET}     # From environment variable
      access-token-expiration: 900000     # 15 minutes
      refresh-token-expiration: 604800000 # 7 days
    refresh-tokens:
      enabled: true             # Enable refresh tokens
      repository:
        type: "postgresql"      # High performance storage
    password-policy:
      min-length: 12            # Stronger for production
      require-special-chars: true
    # --- NEW: Blocklist and Rate Limiter ---
    token-blocklist:
      enabled: true
      type: redis   # Use 'redis' for distributed blocklist in production
    rate-limiter:
      enabled: true
      type: redis   # Use 'redis' for distributed rate limiting in production
      max-requests: 200
      time-window-ms: 60000
    # --- NEW: Cookie Security ---
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
  redirect-https: true
```

👉 **See:
** [Environment Variables](environment.md), [Security Configuration](security.md), [Refresh Token Configuration](refresh-token.md)

### **Mobile API Backend**

Optimized for mobile applications:

```yaml
ricardo:
  auth:
    jwt:
      access-token-expiration: 900000     # 15 minutes for mobile access tokens
      refresh-token-expiration: 2592000000 # 30 days for mobile refresh tokens
    refresh-tokens:
      enabled: true
      max-tokens-per-user: 10   # More tokens for multiple devices
    password-policy:
      require-special-chars: false  # Mobile-friendly
    # --- NEW: Blocklist and Rate Limiter ---
    token-blocklist:
      enabled: true
      type: memory   # or 'redis' for distributed blocklist
    rate-limiter:
      enabled: true
      type: memory   # or 'redis' for distributed rate limiting
      max-requests: 100
      time-window-ms: 60000
    # --- NEW: Cookie Security ---
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
  redirect-https: true
```

👉 **See:** [Mobile API Example](../examples/mobile-api.md), [Refresh Token Configuration](refresh-token.md)

### **High-Security Application**

Maximum security settings:

```yaml
ricardo:
  auth:
    jwt:
      access-token-expiration: 3600000       # 1 hour
      refresh-token-expiration: 604800000    # 7 days
    password-policy:
      min-length: 15
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      prevent-common-passwords: true
    # --- NEW: Blocklist and Rate Limiter ---
    token-blocklist:
      enabled: true
      type: redis   # Use 'redis' for distributed blocklist in high-security apps
    rate-limiter:
      enabled: true
      type: redis   # Use 'redis' for distributed rate limiting in high-security apps
      max-requests: 50
      time-window-ms: 60000
    # --- NEW: Cookie Security ---
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
  redirect-https: true
```

👉 **See:** [Security Configuration](security.md), [Password Policy](password-policy.md)

## 🔧 Configuration Management

### **Development Workflow**

1. **Start with basic configuration:**
   ```yaml
   ricardo:
     auth:
       jwt:
         secret: "development-secret-key"
   ```

2. **Add database:**
   ```yaml
   spring:
     datasource:
       url: jdbc:h2:mem:testdb
   ```

3. **Configure password policy:**
   ```yaml
   ricardo:
     auth:
       password-policy:
         min-length: 8
   ```

4. **Move to production:**
    - Replace secrets with environment variables
    - Use production database
    - Strengthen security policies

### **Environment-Specific Configuration**

#### **Using Spring Profiles**

```yaml
# application.yml (default)
ricardo:
  auth:
    jwt:
      secret: "default-secret"

---
# Development profile
spring:
  config:
    activate:
      on-profile: dev
ricardo:
  auth:
    jwt:
      secret: "dev-secret"
      access-token-expiration: 86400000
      refresh-token-expiration: 604800000

---
# Production profile  
spring:
  config:
    activate:
      on-profile: prod
ricardo:
  auth:
    jwt:
      secret: ${JWT_SECRET}
      access-token-expiration: 900000
      refresh-token-expiration: 604800000
```

#### **Using Environment Variables**

```bash
# Development
export RICARDO_AUTH_JWT_SECRET="dev-secret"
export RICARDO_AUTH_JWT_ACCESS_TOKEN_EXPIRATION="86400000"
export RICARDO_AUTH_JWT_REFRESH_TOKEN_EXPIRATION="604800000"

# Production
export RICARDO_AUTH_JWT_SECRET="prod-secret-from-vault"
export RICARDO_AUTH_JWT_ACCESS_TOKEN_EXPIRATION="900000"
export RICARDO_AUTH_JWT_REFRESH_TOKEN_EXPIRATION="604800000"
```

## 🛠 Configuration Validation

### **Check Your Configuration**

1. **Verify configuration is loaded:**
   ```bash
   curl http://localhost:8080/actuator/configprops | grep ricardo
   ```

2. **Test basic functionality:**
   ```bash
   # Test user creation
   curl -X POST http://localhost:8080/api/users/create \
     -H "Content-Type: application/json" \
     -d '{"username":"test","email":"test@example.com","password":"TestPass@123!"}'
   ```

3. **Check health status:**
   ```bash
   curl http://localhost:8080/actuator/health
   ```

### **Common Configuration Issues**

| Issue                      | Solution                       | Guide                                 |
|----------------------------|--------------------------------|---------------------------------------|
| JWT secret not set         | Add `ricardo.auth.jwt.secret`  | [Basic Configuration](basic.md)       |
| Database connection fails  | Check datasource configuration | [Database Configuration](database.md) |
| Password validation errors | Check password policy settings | [Password Policy](password-policy.md) |
| Authentication fails       | Verify JWT secret consistency  | [Security Configuration](security.md) |

## 📊 Configuration Templates

### **Minimal Template**

```yaml
# Absolute minimum configuration
ricardo:
  auth:
    jwt:
      secret: "${JWT_SECRET:your-fallback-secret-here}"

spring:
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
  jpa:
    hibernate:
      ddl-auto: create-drop
```

### **Complete Template**

```yaml
# Comprehensive configuration example
spring:
  application:
    name: my-app

  datasource:
    url: ${DATABASE_URL:jdbc:h2:mem:testdb}
    username: ${DATABASE_USERNAME:sa}
    password: ${DATABASE_PASSWORD:password}
    driver-class-name: ${DATABASE_DRIVER:org.h2.Driver}

  jpa:
    hibernate:
      ddl-auto: ${DDL_AUTO:create-drop}
    show-sql: ${SHOW_SQL:false}

ricardo:
  auth:
    enabled: ${RICARDO_AUTH_ENABLED:true}

    jwt:
      secret: ${JWT_SECRET}
      access-token-expiration: ${JWT_ACCESS_TOKEN_EXPIRATION:900000}
      refresh-token-expiration: ${JWT_REFRESH_TOKEN_EXPIRATION:604800000}
    refresh-tokens:
      enabled: ${REFRESH_TOKEN_ENABLED:true}
      max-tokens-per-user: ${REFRESH_TOKEN_MAX_TOKENS_PER_USER:5}
      rotate-on-refresh: ${REFRESH_TOKEN_ROTATE_ON_REFRESH:true}
      cleanup-interval: ${REFRESH_TOKEN_CLEANUP_INTERVAL:3600000}
      auto-cleanup: ${REFRESH_TOKEN_AUTO_CLEANUP:true}
      repository:
        type: ${REFRESH_TOKEN_REPOSITORY_TYPE:jpa}
        database:
          refresh-tokens-table: ${REFRESH_TOKEN_TABLE:refresh_tokens}
          schema: ${REFRESH_TOKEN_SCHEMA:}
    password-policy:
      min-length: ${PASSWORD_MIN_LENGTH:8}
      max-length: ${PASSWORD_MAX_LENGTH:128}
      require-uppercase: ${PASSWORD_REQUIRE_UPPERCASE:true}
      require-lowercase: ${PASSWORD_REQUIRE_LOWERCASE:true}
      require-digits: ${PASSWORD_REQUIRE_DIGITS:true}
      require-special-chars: ${PASSWORD_REQUIRE_SPECIAL_CHARS:true}
      prevent-common-passwords: ${PASSWORD_PREVENT_COMMON:true}
    # --- NEW: Blocklist and Rate Limiter ---
    token-blocklist:
      enabled: ${TOKEN_BLOCKLIST_ENABLED:true}
      type: ${TOKEN_BLOCKLIST_TYPE:memory}
    rate-limiter:
      enabled: ${RATE_LIMITER_ENABLED:true}
      type: ${RATE_LIMITER_TYPE:memory}
      max-requests: ${RATE_LIMITER_MAX_REQUESTS:100}
      time-window-ms: ${RATE_LIMITER_TIME_WINDOW_MS:60000}
    # --- NEW: Cookie Security ---
    cookies:
      access:
        secure: ${COOKIE_ACCESS_SECURE:true}
        http-only: ${COOKIE_ACCESS_HTTP_ONLY:true}
        same-site: ${COOKIE_ACCESS_SAME_SITE:Strict}
        path: ${COOKIE_ACCESS_PATH:/}
      refresh:
        secure: ${COOKIE_REFRESH_SECURE:true}
        http-only: ${COOKIE_REFRESH_HTTP_ONLY:true}
        same-site: ${COOKIE_REFRESH_SAME_SITE:Strict}
        path: ${COOKIE_REFRESH_PATH:/api/auth/refresh}
  redirect-https: ${REDIRECT_HTTPS:true}
```

## New Admin Endpoint: Token Revocation

Ricardo Auth provides an admin-only endpoint to revoke any token (access or refresh):

```http
POST /api/auth/revoke
Authorization: Bearer <admin-access-token>
Content-Type: application/json

"<token-to-revoke>"
```

- Only users with `ADMIN` role can call this endpoint.
- Works for both access and refresh tokens.

## 🔗 Quick Links

### **Essential Reading**

- **[Basic Configuration](basic.md)** - Start here for first-time setup
- **[Password Policy](password-policy.md)** 🆕 - Configure password requirements
- **[Environment Variables](environment.md)** - Secure configuration management

### **Production Ready**

- **[Database Configuration](database.md)** - Production database setup
- **[Security Configuration](security.md)** - Production security settings
- **[Advanced Configuration](advanced.md)** - Performance optimization

### **Examples & Troubleshooting**

- **[Configuration Examples](../examples/index.md)** - Real-world configurations
- **[Troubleshooting](../troubleshooting/index.md)** - Common configuration issues

## 🆘 Need Help?

### **Common Questions**

- **"What's the minimum configuration?"** → [Basic Configuration](basic.md#minimum-configuration)
- **"How do I secure for production?"** → [Security Configuration](security.md)
- **"How do I configure passwords?"** → [Password Policy](password-policy.md)
- **"Configuration not working?"** → [Troubleshooting](../troubleshooting/index.md)

### **Get Support**

- 📖 [Full Documentation](../index.md)
- 🐛 [GitHub Issues](https://github.com/RicardoMorim/Auth-Provider/issues)
- 💬 [GitHub Discussions](https://github.com/RicardoMorim/Auth-Provider/discussions)

---

**Ready to configure?** Start with [Basic Configuration](basic.md) for your first setup! 🚀
