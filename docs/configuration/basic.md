# Basic Configuration

> **Breaking Changes in v3.0.0:**
> - **UUID Primary Keys**: All entities now use UUID instead of Long for primary keys
> - **Repository Types**: New `ricardo.auth.repositories.type` configuration (JPA or POSTGRESQL)
> - **Enhanced Decoupling**: Factory pattern and helper classes for custom implementations
> - **CSRF Protection**: Cross-Site Request Forgery protection now enabled by default (NEW)
> - Authentication continues to use secure cookies (`access_token`, `refresh_token`) with `HttpOnly`, `Secure`, and
    `SameSite` flags
> - Database schema requires migration from Long IDs to UUID (see [Database Configuration](database.md))

Get **Ricardo Auth running quickly** with minimal configuration. Perfect for development, prototyping, and getting
started.

## 📋 Quick Navigation

- [Minimum Configuration](#minimum-configuration)
- [Development Setup](#development-setup)
- [Basic Authentication](#basic-authentication)
- [Common Settings](#common-settings)
- [Environment Variables](#environment-variables)
- [Troubleshooting](#troubleshooting)

## Minimum Configuration

**The absolute minimum to get Ricardo Auth working:**

### Step 1: Add Dependency

```xml
<dependency>
    <groupId>io.github.ricardomorim</groupId>
    <artifactId>auth-spring-boot-starter</artifactId>
    <version>3.0.0</version>
</dependency>
```

### Step 2: Set JWT Secret and Repository Type

```yaml
# application.yml
ricardo:
  auth:
    jwt:
      secret: "your-256-bit-secret-key-here-make-it-long-and-secure"
      access-token-expiration: 86400000   # 1 day (default)
      refresh-token-expiration: 604800000 # 7 days (default)
    # New in v3.0.0: Choose repository implementation
    repositories:
      type: JPA  # Options: JPA (default) or POSTGRESQL

```

**That's it!** 🎉 Ricardo Auth is now configured with sensible defaults.

### What You Get By Default

- ✅ JWT authentication with 7-day expiration
- ✅ User registration and login endpoints
- ✅ Password validation (8+ characters)
- ✅ BCrypt password encryption
- ✅ Basic role-based security (`USER` role)
- ✅ In-memory H2 database for quick testing
- ✅ Token blocklist and rate limiting (in-memory or Redis)
- ✅ Secure cookies for tokens
- ✅ `/api/auth/revoke` endpoint for admin token revocation

### What Changed in v2.0.0

- **JWT Configuration:** Added `access-token-expiration` and `refresh-token-expiration` properties.
- **Blocklist/Rate Limiter:** New `token-blocklist` and `rate-limiter` sections.
- **Cookie Security:** New `cookies` section for configuring token cookies.

### What's New in v3.0.0

**🚨 Breaking Changes:**

- **UUID Primary Keys:** All entities now use UUID instead of Long for IDs
- **Enhanced Decoupling:** New factory pattern for user creation
- **PostgreSQL Support:** Native PostgreSQL implementation alongside JPA

**New Features:**

- **Repository Types:** Choose between JPA and PostgreSQL implementations
- **Factory Pattern:** `AuthUserFactory` and `UserFactory` for custom user creation
- **Helper Classes:** `UserRowMapper`, `UserSqlParameterMapper`, `IdConverter`
- **Better Type Safety:** Enhanced generics with Role information

**Repository Type Configuration:**

```properties
# Choose your repository implementation
ricardo.auth.repository.type=JPA    # Default - works with all databases
# OR
ricardo.auth.repository.type=POSTGRESQL  # Optimized for PostgreSQL
```

- **HTTPS Redirect:** New `redirect-https` property to enforce HTTPS.

## Development Setup

### Complete Development Configuration

```yaml
# application-dev.yml
spring:
  profiles:
    active: dev
  
  # H2 Database for Development
  datasource:
    url: jdbc:h2:mem:devdb
    driver-class-name: org.h2.Driver
    username: sa
    password: password
  
  jpa:
    hibernate:
      ddl-auto: create-drop  # Recreate tables on restart
    show-sql: true          # Show SQL queries in console
  
  h2:
    console:
      enabled: true         # Enable H2 web console
      path: /h2-console

# Ricardo Auth Configuration
ricardo:
  auth:
    jwt:
      secret: "dev-secret-key-make-it-long-enough-for-security"
      expiration: 86400000  # 24 hours for development
    controllers:
      auth:
        enabled: true       # Enable /api/auth endpoints
      user:
        enabled: true       # Enable /api/users endpoints

# Logging
logging:
  level:
    com.ricardo.auth: DEBUG
    org.springframework.security: DEBUG

server:
  port: 8080
```

### Dependencies for Development

```xml
<dependencies>
    <!-- Ricardo Auth Starter -->
    <dependency>
        <groupId>io.github.ricardomorim</groupId>
        <artifactId>auth-spring-boot-starter</artifactId>
        <version>3.0.0</version>
    </dependency>
    
    <!-- Spring Boot Web -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- Spring Boot JPA -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    
    <!-- H2 Database (Development) -->
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <scope>runtime</scope>
    </dependency>
    
    <!-- Development Tools -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-devtools</artifactId>
        <scope>runtime</scope>
        <optional>true</optional>
    </dependency>
</dependencies>
```

### Application Class

```java
package com.mycompany.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class MyApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}
```

## Basic Authentication

### Testing Your Setup

**1. Start the application:**

```bash
mvn spring-boot:run
```

**2. Create a test user:**

```bash
curl -X POST http://localhost:8080/api/users/create \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123"
  }'
```

**3. Login to get a JWT token:**

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'
```

**4. Use the token to access protected endpoints:**

```bash
curl -H "Authorization: Bearer YOUR_TOKEN_HERE" \
     http://localhost:8080/api/auth/me
```

### Available Endpoints

| Method | Endpoint            | Description      | Authentication |
|--------|---------------------|------------------|----------------|
| POST   | `/api/users/create` | Create new user  | None           |
| POST   | `/api/auth/login`   | Login user       | None           |
| GET    | `/api/auth/me`      | Get current user | Required       |
| GET    | `/api/users`        | List all users   | Required       |
| GET    | `/api/users/{id}`   | Get user by ID   | Required       |

## Common Settings

### JWT Configuration

```yaml
ricardo:
  auth:
    jwt:
      secret: "your-secret-key"           # Required: 256-bit secret
      expiration: 604800000               # Optional: 7 days (default)
```

### Controller Configuration

```yaml
ricardo:
  auth:
    controllers:
      auth:
        enabled: true                     # Enable /api/auth/* endpoints
      user:
        enabled: true                     # Enable /api/users/* endpoints
```

### Password Policy (Optional)

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 8                       # Minimum password length
      require-uppercase: true             # Require A-Z
      require-lowercase: true             # Require a-z
      require-digits: true                # Require 0-9
      require-special-chars: false       # Require !@#$%^&*
      prevent-common-passwords: true      # Block weak passwords
```

### Database Configuration

```yaml
spring:
  datasource:
    url: jdbc:h2:mem:myapp                # H2 in-memory
    # url: jdbc:h2:file:./data/myapp      # H2 file-based
    driver-class-name: org.h2.Driver
    username: sa
    password: password
  
  jpa:
    hibernate:
      ddl-auto: create-drop               # Development: recreate tables
      # ddl-auto: update                  # Development: update schema
      # ddl-auto: validate                # Production: validate only
    show-sql: true                        # Show SQL queries
```

## Environment Variables

### Using .env Files

Ricardo Auth supports `.env` files for **only 3 specific properties**. Create a `.env` file in your project root:

```env
# .env file - Only these 3 properties support .env override
RICARDO_AUTH_JWT_SECRET=your-256-bit-secret-key-here-make-it-long-and-secure
MAIL_USERNAME=your_smtp_username
MAIL_PASSWORD=your_smtp_password
```

**Note:** Other properties must be configured in `application.yml` - they are **not** supported in `.env` files.

### Complete YAML Configuration

All other configuration must be done in `application.yml`:

```yaml
ricardo:
  auth:
    jwt:
      secret: ${RICARDO_AUTH_JWT_SECRET:your-256-bit-secret-key-here}
      access-token-expiration: 900000     # 15 minutes (default)
      refresh-token-expiration: 604800000 # 7 days (default)
    
    email:
      from-address: "noreply@yourapp.com"
      from-name: "Your App Name"
      host: "smtp.gmail.com"
      port: 587
      password: ${MAIL_PASSWORD:your_smtp_password}
    
    cookies:
      access:
        secure: true
        http-only: true
        same-site: Strict
        path: "/"
      refresh:
        secure: true
        http-only: true
        same-site: Strict
        path: "/api/auth/refresh"
    
    password-policy:
      min-length: 8
      max-length: 128
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: false
      allowed-special-chars: "!@#$%^&*()_+-=[]{}|;:,.<>?"
      prevent-common-passwords: true
      common-passwords-file-path: "/commonpasswords.txt"

spring:
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
```

### Required Environment Variables

```bash
# Only these 3 properties support environment variable override
export RICARDO_AUTH_JWT_SECRET="your-256-bit-secret-key-here"
export MAIL_USERNAME="your_smtp_username"
export MAIL_PASSWORD="your_smtp_password"
```

**Note:** All other configuration must be set in `application.yml` - they do **not** support environment variable
override.

### Setting Environment Variables

**Linux/macOS:**

```bash
export RICARDO_AUTH_JWT_SECRET="your-secret-key"
export MAIL_USERNAME="your_smtp_username"
export MAIL_PASSWORD="your_smtp_password"
```

**Windows:**

```cmd
set RICARDO_AUTH_JWT_SECRET=your-secret-key
set MAIL_USERNAME=your_smtp_username
set MAIL_PASSWORD=your_smtp_password
```

**IDE (IntelliJ IDEA):**

```
Run Configuration → Environment Variables:
RICARDO_AUTH_JWT_SECRET=your-secret-key
MAIL_USERNAME=your_smtp_username
MAIL_PASSWORD=your_smtp_password
```

## Configuration Properties Reference

### Complete v4.0.0 Configuration

Based on `AuthProperties.java`, here are all available configuration properties:

```yaml
ricardo:
  auth:
    # Global Settings
    enabled: true                         # Enable/disable auth module
    redirect-https: true                  # Redirect HTTP to HTTPS in production
    
    # JWT Configuration (REQUIRED)
    jwt:
      secret: "your-256-bit-secret-key-here"       # JWT signing secret (REQUIRED)
      access-token-expiration: 900000              # Access token expiration (ms) - 15 minutes
      refresh-token-expiration: 604800000          # Refresh token expiration (ms) - 7 days
    
    # Controller Configuration
    controllers:
      auth:
        enabled: true                     # Enable /api/auth endpoints
      user:
        enabled: true                     # Enable /api/users endpoints
    
    # Password Policy Configuration
    password-policy:
      min-length: 8                       # Minimum password length
      max-length: 128                     # Maximum password length
      require-uppercase: true             # Require uppercase letters
      require-lowercase: true             # Require lowercase letters
      require-digits: true                # Require digits
      require-special-chars: false        # Require special characters
      allowed-special-chars: "!@#$%^&*()_+-=[]{}|;:,.<>?"  # Allowed special characters
      prevent-common-passwords: true      # Prevent common passwords
      common-passwords-file-path: "/commonpasswords.txt"   # Path to common passwords file
    
    # Refresh Token Configuration
    refresh-tokens:
      enabled: true                       # Enable refresh token functionality
      max-tokens-per-user: 5              # Maximum tokens per user (0 = unlimited)
      rotate-on-refresh: true             # Generate new refresh token on use
      cleanup-interval: 3600000           # Cleanup interval in ms (1 hour)
      auto-cleanup: true                  # Enable automatic cleanup
    
    # Repository Configuration
    repository:
      type: JPA                           # Options: JPA, POSTGRESQL
      database:
        refresh-tokens-table: "refresh_tokens"           # Refresh tokens table name
        password-reset-tokens-table: "password_reset_tokens"  # Password reset tokens table
        schema: ""                        # Database schema (optional)
        url: ""                          # Database URL (optional)
        driver-class-name: ""            # Database driver (optional)
    
    # Rate Limiter Configuration
    rate-limiter:
      enabled: true                       # Enable rate limiting
      type: MEMORY                        # Options: MEMORY, REDIS
      max-requests: 150                   # Max requests per time window
      time-window-ms: 60000               # Time window in milliseconds
    
    # Token Blocklist Configuration
    token-blocklist:
      enabled: true                       # Enable token revocation
      type: MEMORY                        # Options: MEMORY, REDIS
    
    # Redis Configuration (when using REDIS type)
    redis:
      host: "localhost"                   # Redis host
      port: 6379                          # Redis port
      password: ""                        # Redis password (optional)
      database: 0                         # Redis database number
    
    # Cookie Security Configuration
    cookies:
      access:
        secure: true                      # Secure flag (HTTPS only)
        http-only: true                   # Prevent JavaScript access
        same-site: STRICT                 # Options: STRICT, LAX, NONE
        path: "/"                         # Cookie path
      refresh:
        secure: true                      # Secure flag (HTTPS only)
        http-only: true                   # Prevent JavaScript access
        same-site: STRICT                 # Options: STRICT, LAX, NONE
        path: "/api/auth/refresh"         # Cookie path
    
    # Password Reset Configuration
    password-reset:
      enabled: true                       # Enable password reset functionality
      token-expiry-hours: 1               # Reset token expiry time (hours)
      max-attempts: 3                     # Max reset attempts
      time-window-ms: 3600000             # Time window for attempts (ms)
      enable-cleanup: true                # Enable automatic token cleanup
      cleanup-interval-hours: 24         # Cleanup interval (hours)
      token-length: 32                    # Reset token length
      require-https: true                 # Require HTTPS for reset URLs
    
    # Email Configuration
    email:
      from-address: "noreply@example.com" # Sender email address
      password: ""                        # Email password (use MAIL_PASSWORD env var)
      host: "smtp.gmail.com"              # SMTP host
      port: 587                           # SMTP port
      from-name: "Auth Service"           # Sender display name
      reset-subject: "Password Reset Request"  # Subject for password reset emails
      reset-template: "default"          # Email template name
    
    # Role Management Configuration
    role-management:
      enable-role-events: true            # Enable role change events
      require-admin-for-role-changes: true        # Require admin for role changes
      allow-self-role-modification: false          # Allow users to modify their own roles

# Spring Configuration (Required)
spring:
  datasource:
    url: jdbc:h2:mem:testdb              # Database URL
    username: sa                         # Database username
    password: password                   # Database password
    driver-class-name: org.h2.Driver     # Database driver
  
  jpa:
    hibernate:
      ddl-auto: create-drop              # Schema management: create-drop, update, validate
    show-sql: false                      # Show SQL queries in logs
  
  mail:
    host: "smtp.gmail.com"               # SMTP host
    port: 587                            # SMTP port
    username: ${MAIL_USERNAME:your_username}      # SMTP username (from env var)
    password: ${MAIL_PASSWORD:your_password}      # SMTP password (from env var)
    properties:
      mail:
        smtp:
          auth: true                     # Enable SMTP authentication
          starttls:
            enable: true                 # Enable STARTTLS
  
  data:
    redis:                               # Redis configuration (if using REDIS type)
      host: "localhost"                  # Redis host
      port: 6379                         # Redis port
      password: ""                       # Redis password (optional)
```

### Production Environment Configuration

```yaml
# application-prod.yml
ricardo:
  auth:
    jwt:
      secret: "${RICARDO_AUTH_JWT_SECRET}"
      access-token-expiration: 3600000    # 1 hour for production
      refresh-token-expiration: 604800000 # 7 days
    
    email:
      from-address: "${RICARDO_AUTH_EMAIL_FROM_ADDRESS:noreply@yourdomain.com}"
      from-name: "${RICARDO_AUTH_EMAIL_FROM_NAME:Your App}"
    
    cors:
      allowed-origins: "${RICARDO_AUTH_CORS_ALLOWED_ORIGINS}"
      allow-credentials: true
    
    rate-limiter:
      type: redis                         # Use Redis for distributed systems
      enabled: true
      max-requests: 50                    # Lower limit for production
      time-window-ms: 60000
    
    token-blocklist:
      type: redis                         # Use Redis for distributed systems
      enabled: true
    
    cookies:
      access:
        secure: true                      # Always true in production
        same-site: Strict
      refresh:
        secure: true                      # Always true in production
        same-site: Strict
    
    redirect-https: true                  # Enforce HTTPS

# Spring Configuration
spring:
  datasource:
    url: "${SPRING_DATASOURCE_URL}"
    username: "${SPRING_DATASOURCE_USERNAME}"
    password: "${SPRING_DATASOURCE_PASSWORD}"
    driver-class-name: org.postgresql.Driver
  
  jpa:
    hibernate:
      ddl-auto: validate                  # Don't modify schema in production
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
        format_sql: false
    show-sql: false
  
  # Redis Configuration (if using Redis for rate limiting/blocklist)
  data:
    redis:
      host: "${SPRING_DATA_REDIS_HOST:localhost}"
      port: "${SPRING_DATA_REDIS_PORT:6379}"
      password: "${SPRING_DATA_REDIS_PASSWORD:}"
  
  # Email Configuration (if using SMTP)
  mail:
    host: "${SPRING_MAIL_HOST}"
    port: "${SPRING_MAIL_PORT:587}"
    username: "${SPRING_MAIL_USERNAME}"
    password: "${SPRING_MAIL_PASSWORD}"
    properties:
      mail:
        smtp:
          auth: true
          starttls:
            enable: true

# Server Configuration
server:
  port: "${SERVER_PORT:8080}"
  servlet:
    context-path: "${SERVER_SERVLET_CONTEXT_PATH:}"

# Logging
logging:
  level:
    root: INFO
    com.ricardo.auth: INFO
    org.springframework.security: WARN
  pattern:
    file: "%d{ISO8601} [%thread] %-5level %logger{36} - %msg%n"
    console: "%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n"
```

### Spring Boot Integration

```yaml
spring:
  application:
    name: my-app
  
  # Database
  datasource:
    url: jdbc:h2:mem:myapp
    driver-class-name: org.h2.Driver
    username: sa
    password: password
  
  # JPA
  jpa:
    hibernate:
      ddl-auto: create-drop
    show-sql: true
    database-platform: org.hibernate.dialect.H2Dialect
  
  # H2 Console
  h2:
    console:
      enabled: true
      path: /h2-console

# Server
server:
  port: 8080

# Logging
logging:
  level:
    root: INFO
    com.ricardo.auth: DEBUG
```

## Configuration Validation

Ricardo Auth validates your configuration on startup:

### ✅ Valid Configuration

```yaml
ricardo:
  auth:
    jwt:
      secret: "this-is-a-valid-256-bit-secret-key-for-jwt-signing"
```

### ❌ Invalid Configuration

```yaml
ricardo:
  auth:
    jwt:
      secret: "too-short"  # Will cause startup failure
```

**Error Message:**

```
***************************
APPLICATION FAILED TO START
***************************

Description:
JWT secret must be at least 256 bits (32 characters) long

Action:
Configure a longer JWT secret in application.yml
```

## Troubleshooting

### Common Issues

**1. Application Won't Start**

```
Error: Property 'ricardo.auth.jwt.secret' is required
```

**Solution:** Add JWT secret to your configuration.

**2. Database Connection Issues**

```
Error: Failed to configure a DataSource
```

**Solution:** Add JPA and database dependencies to your `pom.xml`.

**3. Login Returns 401**

```
Error: Bad credentials
```

**Solution:** Verify user exists and password is correct.

### Debug Configuration

```yaml
logging:
  level:
    com.ricardo.auth: TRACE              # Detailed auth logs
    org.springframework.security: DEBUG  # Security logs
    org.springframework.web: DEBUG       # Web request logs
    org.hibernate.SQL: DEBUG             # SQL queries
```

### Health Check

```bash
# Check if application is running
curl http://localhost:8080/actuator/health

# Check H2 database (if enabled)
# Visit: http://localhost:8080/h2-console
```

### Quick Verification

```bash
# 1. Create user
curl -X POST http://localhost:8080/api/users/create \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@example.com","password":"password123"}'

# 2. Login
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

# 3. Test protected endpoint (use token from step 2)
curl http://localhost:8080/api/auth/me --cookie "access_token=YOUR_ACCESS_TOKEN_HERE"
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

## Next Steps

Once you have basic configuration working:

1. **🔐 Security:** [Security Configuration Guide](password-policy.md)
2. **🗄️ Database:** [Database Configuration Guide](database.md)
3. **📚 Examples:** [Implementation Examples](../examples/index.md)
