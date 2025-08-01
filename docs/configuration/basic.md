# Basic Configuration

> **Breaking Change (v2.0.0):**
> - Authentication now uses secure cookies (`access_token`, `refresh_token`) with `HttpOnly`, `Secure`, and `SameSite`
    flags by default. You must use HTTPS in production or set `ricardo.auth.cookies.access.secure: false` for local
    development only.
> - New blocklist and rate limiting features are available (see below).
> - New `/api/auth/revoke` admin endpoint for revoking tokens (access or refresh).

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
    <version>2.0.0</version>
</dependency>
```

### Step 2: Set JWT Secret

```yaml
# application.yml
ricardo:
  auth:
    jwt:
      secret: "your-256-bit-secret-key-here-make-it-long-and-secure"
      access-token-expiration: 86400000   # 1 day (default)
      refresh-token-expiration: 604800000 # 7 days (default)

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
        <version>1.1.0</version>
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

### Required Environment Variables

```bash
# JWT Secret (Required)
export RICARDO_AUTH_JWT_SECRET="your-256-bit-secret-key-here"
```

### Optional Environment Variables

```bash
# JWT Token Expiration (Optional, default: 7 days)
export RICARDO_AUTH_JWT_EXPIRATION="86400000"  # 1 day

# Enable/Disable Features (Optional, default: true)
export RICARDO_AUTH_ENABLED="true"
export RICARDO_AUTH_CONTROLLERS_AUTH_ENABLED="true"
export RICARDO_AUTH_CONTROLLERS_USER_ENABLED="true"

# Database Configuration (Optional)
export SPRING_DATASOURCE_URL="jdbc:h2:mem:myapp"
export SPRING_DATASOURCE_USERNAME="sa"
export SPRING_DATASOURCE_PASSWORD="password"
```

### Setting Environment Variables

**Linux/macOS:**

```bash
export RICARDO_AUTH_JWT_SECRET="your-secret-key"
export RICARDO_AUTH_JWT_EXPIRATION="86400000"
```

**Windows:**

```cmd
set RICARDO_AUTH_JWT_SECRET=your-secret-key
set RICARDO_AUTH_JWT_EXPIRATION=86400000
```

**IDE (IntelliJ IDEA):**

```
Run Configuration → Environment Variables:
RICARDO_AUTH_JWT_SECRET=your-secret-key
RICARDO_AUTH_JWT_EXPIRATION=86400000
```

## Configuration Properties Reference

### Complete Basic Configuration

```yaml
ricardo:
  auth:
    enabled: true                         # Enable/disable auth module
    jwt:
      secret: "your-secret-key"           # JWT signing secret (REQUIRED)
      access-token-expiration: 604800000   # Access token expiration (ms)
      refresh-token-expiration: 604800000  # Refresh token expiration (ms)
    controllers:
      auth:
        enabled: true                     # Enable /api/auth endpoints
      user:
        enabled: true                     # Enable /api/users endpoints
    password-policy:
      min-length: 8                       # Minimum password length
      max-length: 128                     # Maximum password length
      require-uppercase: true             # Require uppercase letters
      require-lowercase: true             # Require lowercase letters
      require-digits: true                # Require digits
      require-special-chars: false        # Require special characters
      special-characters: "!@#$%^&*()"   # Allowed special characters
      prevent-common-passwords: true      # Prevent common passwords
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
        secure: true      # Set to false for local dev only
        http-only: true
        same-site: Strict # Strict/Lax/None
        path: /
      refresh:
        secure: true
        http-only: true
        same-site: Strict
        path: /api/auth/refresh
  redirect-https: true   # Enforce HTTPS (recommended for production)
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
