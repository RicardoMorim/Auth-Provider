# Ricardo Auth Spring Boot Starter

[![Maven Central](https://img.shields.io/maven-central/v/io.github.ricardomorim/auth-spring-boot-starter?color=blue&label=Maven%20Central)](https://central.sonatype.com/artifact/io.github.ricardomorim/auth-spring-boot-starter)
[![GitHub release](https://img.shields.io/github/release/RicardoMorim/Auth-Provider.svg)](https://github.com/RicardoMorim/Auth-Provider/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)](https://github.com/RicardoMorim/Auth-Provider)
[![Maintenance](https://img.shields.io/badge/Maintained-Yes-green.svg)](https://github.com/RicardoMorim/Auth-Provider/graphs/commit-activity)

A **plug-and-play** Spring Boot starter that adds JWT authentication and user management to your application with
minimal configuration required.

> 🚀 **Zero-configuration setup** - Just add the dependency and you're ready to go!  
> 🔐 **Production-ready security** - Built-in password policies, JWT tokens, CSRF protection, and role-based access  
> 📚 **Complete documentation** - Comprehensive guides for setup, configuration, and deployment  
> 📈 **BenchMark results** - This library was stress tested with 100k users! Find the results [here](./benchmark_results/Conclusions.md)

## ✨ What You Get

**Authentication & Security**

- 🔑 JWT access and refresh token generation, validation, and refresh via secure cookies
- 🔄 Secure refresh token system with automatic rotation
- 🛡️ Configurable password policies with strength validation
- 🔒 BCrypt password encryption
- 👥 Role-based access control (RBAC) with full role management API
- 🚫 Protection against common weak passwords
- 🗄️ Flexible token storage (JPA/PostgreSQL)
- ⛔ Token blocklist (in-memory or Redis) for instant token revocation
- 🚦 Rate limiting (in-memory or Redis) for brute-force and abuse protection
- 🍪 Secure HTTP-only cookies with configurable security flags
- 🛡️ CSRF protection with cookie-based tokens for enhanced security
- 📧 Password reset system with email integration and OWASP compliance
- 🌐 Comprehensive CORS configuration with credentials support
- 📖 Complete OpenAPI/Swagger documentation integration

**Ready-to-Use API Endpoints**

- `/api/auth/login` - User authentication with secure cookies
- `/api/auth/refresh` - Refresh access token using refresh cookie
- `/api/auth/register` - User registration
- `/api/auth/revoke` - Revoke tokens (ADMIN only)
- `/api/auth/me` - Get current user information
- `/api/auth/password-reset/request` - Request password reset via email
- `/api/auth/password-reset/confirm` - Confirm password reset with token
- `/api/users/*` - Complete user management CRUD
- `/api/roles/*` - Role management API with proper authorization

**Developer Experience**

- 🚀 **Zero-configuration** - Works out of the box with sensible defaults
- ⚙️ **Highly customizable** - Configure everything through `application.yml`
- 🧪 **Test-friendly** - Includes test utilities and examples
- 📖 **Comprehensive docs** - Step-by-step guides for all use cases

**Production Ready**

- 🏗️ Clean architecture with Domain-Driven Design principles
- 🔧 Spring Boot auto-configuration
- 📊 Built-in error handling and validation
- 🌍 Environment-specific configuration support

## 📦 Installation

## ⚙️ Quick Setup

### 1. Add Dependency

```xml

<dependency>
    <groupId>io.github.ricardomorim</groupId>
    <artifactId>auth-spring-boot-starter</artifactId>
    <version>4.0.2</version>
</dependency>
```

### 2. Configure with .env File (Recommended)

Create a `.env` file in your project root (optional - only these 3 properties support .env override):

```env
# Required Configuration
RICARDO_AUTH_JWT_SECRET=your-256-bit-secret-key-here-make-it-long-and-secure

# Email Configuration (for password reset)
MAIL_USERNAME=your_smtp_username
MAIL_PASSWORD=your_smtp_password
```

Add to your `application.yml`:

```yaml
ricardo:
  auth:
    jwt:
      secret: "your-256-bit-secret-key-here-make-it-long-and-secure"
    email:
      from-address: "noreply@yourapp.com"
      from-name: "Your App Name"
      host: "smtp.gmail.com"
      port: 587

# Standard Spring configuration for database and email
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/yourdb
    username: your_db_user
    password: your_db_password
  mail:
    host: smtp.gmail.com
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

### 3. Alternative: Direct YAML Configuration

```yaml
ricardo:
  auth:
    jwt:
      secret: "your-256-bit-secret-key-here-make-it-long-and-secure"
    email:
      from-address: "noreply@yourapp.com"
      from-name: "Your App Name"
      host: "smtp.gmail.com"
      port: 587

# Standard Spring configuration
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/yourdb
    username: your_db_user
    password: your_db_password
  mail:
    host: smtp.gmail.com
    port: 587
    username: your_smtp_username
    password: your_smtp_password
    properties:
      mail:
        smtp:
          auth: true
          starttls:
            enable: true
```

### 4. That's It! 🎉

Your application now has:

- ✅ JWT authentication with secure cookies
- ✅ User registration and management
- ✅ Password reset with email
- ✅ Role-based access control
- ✅ CORS support for frontends
- ✅ OpenAPI documentation at `/swagger-ui.html`

3. Add the dependency:

```xml

<dependency>
    <groupId>io.github.ricardomorim</groupId>
    <artifactId>auth-spring-boot-starter</artifactId>
    <version>{latest version release}</version>
</dependency>
```

## 🚨 Breaking Changes in v4.0.0

**New Features in v4.0.0:**

**What's New:**

- **Password Reset System:** OWASP-compliant password reset with email integration
- **Role Management API:** Full CRUD operations for roles with proper authorization
- **OpenAPI Documentation:** Complete Swagger/OpenAPI integration with interactive documentation
- **Enhanced Input Sanitization:** Improved validation and sanitization for security
- **Better Exception Handling:** Enhanced error responses and exception management
- **Domain Events:** Comprehensive audit trail with domain event publishing

**Previous Breaking Changes (Cookie Authentication):**

- **Cookie Authentication (v2.0.0):** All endpoints use secure HTTP-only cookies (`access_token`, `refresh_token`)
- **HTTPS Required (v2.0.0):** Secure cookies require HTTPS in production environments
- **UUID Primary Keys (v3.0.0):** All entities now use UUID instead of Long for primary keys
- **CSRF Protection (v3.0.0):** CSRF protection enabled by default for enhanced security

**What You Need to Update for v4.0.0:**

- **Email Configuration:** Configure SMTP settings for password reset functionality
- **Role Management:** Update any custom role management code to use new API
- **OpenAPI:** Interactive API documentation now available at `/swagger-ui.html`

**Migration Guide:** See [Security Guide](docs/security-guide.md) and [Configuration Guide](docs/configuration/) for
detailed migration steps.

## ⚡ Quick Start

> **Prerequisites:** Java 17+, Maven/Gradle, and an existing Spring Boot project

### Step 1: Add the Dependency

```xml

<dependency>
    <groupId>io.github.ricardomorim</groupId>
    <artifactId>auth-spring-boot-starter</artifactId>
    <version>4.0.0</version>
</dependency>

        <!-- Required: JPA support -->
<dependency>
<groupId>org.springframework.boot</groupId>
<artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>

        <!-- Choose your database (H2 for quick testing) -->
<dependency>
<groupId>com.h2database</groupId>
<artifactId>h2</artifactId>
<scope>runtime</scope>
</dependency>
```

### Step 2: Configure Database & JWT Secret

Add to your `application.yml`:

```yaml
# Database configuration
spring:
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
    username: sa
    password: password
  jpa:
    hibernate:
      ddl-auto: create-drop

# Required: JWT configuration
ricardo:
  auth:
    jwt:
      secret: "your-256-bit-secret-key-here-make-it-long-and-secure"
      expiration: 604800000  # 7 days
```

### Step 3: Start Your Application

```java

@SpringBootApplication
public class MyApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}
```

### Step 4: Test the API

**Create a user:**

```bash
curl -X POST http://localhost:8080/api/users/create \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com", 
    "password": "SecurePass@123!"
  }'
```

**Login to get JWT tokens:**

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass@123!"
  }'
```

**Refresh your access token:**

```bash
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN_HERE"
  }'
```

**Use the access token to access protected endpoints (cookie-based authentication):**

```bash
curl --cookie "access_token=YOUR_ACCESS_TOKEN_HERE" \
     http://localhost:8080/api/auth/me
```

🎉 **That's it!** Your Spring Boot app now has complete JWT authentication and user management.

> � **New to Ricardo Auth?** Check out our [5-minute Getting Started Guide](docs/getting-started.md)  
> �💡 **Need more control?** See the [Configuration Guide](docs/configuration-guide.md) for advanced options.

## 📖 Documentation

| Guide                                                  | Purpose                  | When to Use          |
|--------------------------------------------------------|--------------------------|----------------------|
| **[Configuration Guide](docs/configuration-guide.md)** | Complete setup options   | Customizing behavior |
| **[API Reference](docs/api-reference.md)**             | All endpoints & examples | Frontend integration |
| **[Security Guide](docs/security-guide.md)**           | Production security      | Deploying safely     |
| **[Examples](docs/examples.md)**                       | Real-world use cases     | Learning patterns    |
| **[Troubleshooting](docs/troubleshooting.md)**         | Common issues & fixes    | Debugging problems   |

## 🔧 Configuration

### Application Properties

Configure the starter using `application.yml` or `application.properties`:

```yaml
ricardo:
  auth:
    enabled: true
    jwt:
      secret: "your-secret-key"
      access-token-expiration: 900000
      refresh-token-expiration: 604800000
    refresh-tokens:
      enabled: true
      max-tokens-per-user: 5
      rotate-on-refresh: true
      cleanup-interval: 3600000
      auto-cleanup: true
      repository:
        type: "jpa" # or "postgresql"
        database:
          refresh-tokens-table: "refresh_tokens"
    controllers:
      auth:
        enabled: true
      user:
        enabled: true
    # Token blocklist (token revocation)
    token-blocklist:
      enabled: true
      type: memory # memory|redis
    # Rate limiting
    rate-limiter:
      enabled: true
      type: memory # memory|redis
      max-requests: 100
      time-window-ms: 60000
    # Secure cookies for tokens
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
    # Force HTTPS (recommended in production)
    redirect-https: true
    # CORS configuration
    cors:
      allowed-origins: [ "http://localhost:3000", "https://yourdomain.com" ]
      allowed-methods: [ "GET", "POST", "PUT", "DELETE", "OPTIONS" ]
      allowed-headers: [ "*" ]
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
    # Redis configuration (if using Redis for blocklist/rate-limiter)
    redis:
      host: localhost
      port: 6379
      password: ""
      database: 0
```

#### Exemplos de configuração para blocklist e rate limiting com Redis

```yaml
ricardo:
  auth:
    token-blocklist:
      enabled: true
      type: redis
    rate-limiter:
      enabled: true
      type: redis
    redis:
      host: redis-server
      port: 6379
      password: "senha"
      database: 0
    cors:
      allowed-origins: [ "https://yourdomain.com" ]
      allow-credentials: true
    email:
      enabled: true
      from: "noreply@yourdomain.com"
      reset-url-template: "https://yourdomain.com/reset-password?token={token}"
```

### Password Policy Configuration

Configure password requirements to enhance security:

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 8                         # Minimum password length
      max-length: 128                       # Maximum password length  
      require-uppercase: true               # Require uppercase letters
      require-lowercase: true               # Require lowercase letters
      require-digits: true                  # Require numeric digits
      require-special-chars: false          # Require special characters
      allowed-special-chars: "!@#$%^&*()_+-=[]{}|;:,.<>?"  # Allowed special characters
      prevent-common-passwords: true        # Block common passwords
      common-passwords-file-path: "/commonpasswords.txt"   # Custom password list
```

**Example secure password**: `MySecure@Pass123!`

### Environment Variables

For production deployments, use environment variables:

```bash
RICARDO_AUTH_JWT_SECRET=your-very-secure-secret-key-here
RICARDO_AUTH_JWT_EXPIRATION=604800000
```

### Required Dependencies

The starter requires a JPA implementation. Add to your `pom.xml`:

```xml

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>

        <!-- Choose your database -->
<dependency>
<groupId>com.h2database</groupId>
<artifactId>h2</artifactId>
<scope>runtime</scope>
</dependency>
```

## 🛠 API Endpoints

### Authentication Endpoints

#### POST `/api/auth/login`

Authenticates the user and returns tokens in secure cookies.

#### POST `/api/auth/refresh`

Generates a new access token using the refresh token from the cookie.

#### POST `/api/auth/revoke` (ADMIN only)

Revokes an access or refresh token. Example usage:

```bash
curl -X POST http://localhost:8080/api/auth/revoke \
  --cookie "access_token=ADMIN_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '"TOKEN_TO_REVOKE"'
```

#### POST `/api/auth/password-reset/request`

Requests a password reset via email.

```bash
curl -X POST http://localhost:8080/api/auth/password-reset/request \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

#### POST `/api/auth/password-reset/confirm`

Confirms password reset with token from email.

```bash
curl -X POST http://localhost:8080/api/auth/password-reset/confirm \
  -H "Content-Type: application/json" \
  -d '{
    "token": "reset-token-from-email",
    "newPassword": "NewSecurePass@123!"
  }'
```

#### GET `/api/auth/me`

Returns information about the authenticated user.

**Authentication:**

- All endpoints use secure HTTP-only cookies (`access_token`, `refresh_token`) for authentication
- CORS must be configured to allow credentials from your frontend domain
- HTTPS is required in production for secure cookies to function properly

**Response:**

```json
{
  "username": "user@example.com",
  "authorities": [
    "ROLE_USER"
  ]
}
```

### User Management Endpoints

#### POST `/api/users/create`

Create a new user account with password policy validation.

**Request:**

```json
{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "SecurePass@123!"
}
```

**Password Requirements:**

- Minimum 10 characters (configurable)
- At least one uppercase letter
- At least one lowercase letter
- At least one numeric digit
- At least one special character: `!@#$%^&*()`
- Not in common passwords list

**Response (Success):**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "johndoe",
  "email": "john@example.com"
}
```

**Response (Example Password Policy Error):**

```json
{
  "error": "Bad Request",
  "message": "Password must contain at least one uppercase letter",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### GET `/api/users/{id}`

Get user by ID (requires authentication).

**Response:**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "johndoe",
  "email": "john@example.com"
}
```

#### GET `/api/users/email/{email}`

Get user by email (requires authentication).

#### GET `/api/users/exists/{email}`

Check if a user exists by email.

**Response:**

```json
true
```

#### PUT `/api/users/update/{id}`

Update user information (requires ADMIN role or ownership).

#### DELETE `/api/users/delete/{id}`

Delete a user (requires ADMIN role or ownership).

### Role Management Endpoints

#### GET `/api/roles`

Get all available roles (requires authentication).

**Response:**

```json
[
  {
    "id": 1,
    "name": "ROLE_USER",
    "description": "Standard user role"
  },
  {
    "id": 2,
    "name": "ROLE_ADMIN",
    "description": "Administrator role"
  }
]
```

#### POST `/api/roles` (ADMIN only)

Create a new role.

**Request:**

```json
{
  "name": "ROLE_MODERATOR",
  "description": "Moderator role with limited admin privileges"
}
```

#### PUT `/api/roles/{id}` (ADMIN only)

Update an existing role.

#### DELETE `/api/roles/{id}` (ADMIN only)

Delete a role (if not assigned to any users).

## 🔐 Security

### Cookie-Based Tokens (BREAKING CHANGE)

Tokens are now sent via HTTP-only, Secure cookies with configurable flags (Secure, SameSite, Path). This increases
protection against XSS and CSRF.

- By default, cookies are `Secure` and `SameSite=Strict`.
- Cookies require HTTPS in production (`redirect-https: true`).
- The frontend must send cookies automatically with each request.
- The Authorization header is no longer used for authentication (except for legacy user endpoints).

### HTTPS Enforcement

By default, the starter enforces HTTPS in production. For development, you can disable it:

```yaml
ricardo:
  auth:
    redirect-https: false
```

### Token Blocklist

Tokens can be revoked instantly (global logout, admin revocation, etc). Supports in-memory or Redis blocklist.

### Rate Limiting

Protects sensitive endpoints from brute-force and abuse. Supports in-memory or Redis for distributed environments.

## 🚨 Breaking Changes & Migration Notes

- **All authentication now uses secure HTTP-only cookies instead of Authorization headers**
- **CORS configuration is required for frontend applications**
- **HTTPS is required in production for secure cookies to function**
- **Email configuration is required for password reset functionality**
- **Enhanced security with rate limiting and input validation enabled by default**
- **Complete OpenAPI documentation available at `/swagger-ui.html`**

## 🎯 Usage Examples

### Basic Spring Boot Application

```java

@SpringBootApplication
public class MyApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}
```

### Custom User Entity (Optional)

You can extend the provided User entity:

```java

@Entity
public class CustomUser extends User {
    private String firstName;
    private String lastName;

    // constructors, getters, setters
}
```

### Custom JWT Claims

Inject the JwtService to customize token generation:

```java

@Service
public class CustomAuthService {

    private final JwtService jwtService;

    public CustomAuthService(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    public String generateCustomToken(String username, Collection<? extends GrantedAuthority> authorities) {
        return jwtService.generateToken(username, authorities);
    }
}
```

## 🔧 Customization

### Disable Controllers

Disable specific controllers if you want to implement your own:

```yaml
ricardo:
  auth:
    controllers:
      auth:
        enabled: false  # Disable auth endpoints
      user:
        enabled: true   # Keep user endpoints
```

### Custom Security Configuration

Override the default security configuration:

```java

@Configuration
@EnableWebSecurity
public class CustomSecurityConfig {

    @Bean
    @Primary
    public SecurityFilterChain customFilterChain(HttpSecurity http) throws Exception {
        // Your custom security configuration
        return http.build();
    }
}
```

### Custom User Service

Implement your own user service:

```java

@Service
@Primary
public class CustomUserService implements UserService<User, Long> {
    // Your implementation
}
```

## 🚨 Troubleshooting

### Common Issues

#### 1. "JWT secret not configured"

**Problem:** Missing or empty JWT secret.
**Solution:** Set `ricardo.auth.jwt.secret` in your configuration.

#### 2. "No qualifying bean of type 'EntityManagerFactory'"

**Problem:** Missing JPA dependency.
**Solution:** Add `spring-boot-starter-data-jpa` to your dependencies.

#### 3. "Table 'USER' doesn't exist"

**Problem:** Database schema not created.
**Solution:** Set `spring.jpa.hibernate.ddl-auto=create-drop` for development.

#### 4. Authentication always fails

**Problem:** Incorrect password encoding or user not found.
**Solution:** Ensure user exists and password is correctly encoded.

### Debug Mode

Enable debug logging:

```yaml
logging:
  level:
    com.ricardo.auth: DEBUG
    org.springframework.security: DEBUG
```

## � Production Deployment

### Environment Configuration

Create production environment files:

**`.env.production`:**

```env
# Only these 3 properties support .env override
RICARDO_AUTH_JWT_SECRET=generate-a-secure-256-bit-secret-key-for-production-use
MAIL_USERNAME=your_smtp_username
MAIL_PASSWORD=your_smtp_password
```

**`application-prod.yml`:**

```yaml
spring:
  profiles:
    active: prod

  datasource:
    url: "jdbc:postgresql://your-db-host:5432/your_production_db"
    username: "your_db_user"
    password: "your_secure_db_password"
    driver-class-name: org.postgresql.Driver

  jpa:
    hibernate:
      ddl-auto: validate  # Don't auto-create tables in production
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
    show-sql: false

  mail:
    host: "smtp.yourprovider.com"
    port: 587
    username: ${MAIL_USERNAME:your_smtp_username}
    password: ${MAIL_PASSWORD:your_smtp_password}
    properties:
      mail:
        smtp:
          auth: true
          starttls:
            enable: true

  data:
    redis:
      host: your-redis-host
      port: 6379
      password: your_redis_password

ricardo:
  auth:
    jwt:
      secret: ${RICARDO_AUTH_JWT_SECRET:generate-a-secure-256-bit-secret-key-for-production-use}
      access-token-expiration: 3600000    # 1 hour for production
      refresh-token-expiration: 604800000 # 7 days

    email:
      from-address: "noreply@yourapp.com"
      from-name: "Your Application"
      host: "smtp.yourprovider.com"
      port: 587

    rate-limiter:
      type: redis
      enabled: true
      max-requests: 50      # Lower for production
      time-window-ms: 60000

    token-blocklist:
      type: redis
      enabled: true

    cookies:
      access:
        secure: true        # Always true in production
        same-site: Strict
      refresh:
        secure: true
        same-site: Strict

    redirect-https: true    # Enforce HTTPS

# Logging
logging:
  level:
    root: INFO
    com.ricardo.auth: INFO
  file:
    name: logs/auth-provider.log
```

### Docker Deployment

**`Dockerfile`:**

```dockerfile
FROM openjdk:17-jdk-slim

WORKDIR /app

COPY target/your-app.jar app.jar
COPY .env.production .env

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "-Dspring.profiles.active=prod", "app.jar"]
```

**`docker-compose.yml`:**

```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
    depends_on:
      - postgres
      - redis
    volumes:
      - ./logs:/app/logs

  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: your_production_db
      POSTGRES_USER: your_db_user
      POSTGRES_PASSWORD: your_secure_db_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass your_redis_password
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

### Production Checklist

- [ ] **Security**: Generate secure JWT secret (256+ bit)
- [ ] **HTTPS**: Configure SSL/TLS certificates
- [ ] **CORS**: Configure allowed origins for your frontend
- [ ] **Database**: Use PostgreSQL or MySQL (not H2)
- [ ] **Redis**: Configure Redis for distributed rate limiting/blocklist
- [ ] **Email**: Configure SMTP for password reset functionality
- [ ] **Monitoring**: Set up health checks and logging
- [ ] **Backup**: Configure database backups
- [ ] **Firewall**: Restrict database/Redis access
- [ ] **Environment**: Use environment variables for secrets

## �📊 Monitoring and Health

The starter exposes actuator endpoints for monitoring:

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
```

## 🚀 Project Status

This project is **production-ready** for its current feature set:

- ✅ JWT Authentication with Refresh Tokens
- ✅ User Management CRUD
- ✅ Password Policy System
- ✅ Role-Based Access Control
- ✅ Multiple Database Support

**Future enhancements** are planned based on community needs and contributions. See [CHANGELOG.md](CHANGELOG.md) for
details.

## 📈 Benchmarks

We ran end-to-end benchmarks comparing the system with database indexes and cache enabled vs. without indexes.

- Read-heavy operations: with indexes, throughput improved by ~21% and average latency dropped ~22% in sequential reads.
- Listing/pagination: without indexes, getAllUsers-style queries were up to ~73x slower on large datasets.
- Concurrent load: per-request latency roughly doubled without indexes; with indexes the system sustained higher RPS.
- Database view: aggregate DB latency increased from ~0.8 ms to ~6 ms on average without indexes (P99: ~6 ms → ~46 ms).
- Writes: user creation performance was virtually identical in both scenarios (no meaningful regression with indexes).

Notes:

- One concurrent run with indexes hit a client-side TCP port exhaustion on Windows, which affected reported success
  rate, not server stability.
- Full methodology, numbers, and raw results are documented here: [benchmarks](./benchmark_results/Conclusions.md).

## 🤝 Contributing

This project is actively maintained. Bug fixes and security issues will be addressed promptly. Feature contributions are
welcome!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- [GitHub Repository](https://github.com/RicardoMorim/Auth-Provider)
- [Issues](https://github.com/RicardoMorim/Auth-Provider/issues)
- [Maven Central](https://search.maven.org/artifact/io.github.ricardomorim/auth-spring-boot-starter)

## 👨‍💻 Author

**Ricardo**

- Email: ricardomorim05@gmail.com
- Portfolio: [ricardoportfolio.vercel.app](https://ricardoportfolio.vercel.app)
- GitHub: [@RicardoMorim](https://github.com/RicardoMorim)
- LinkedIn: [Ricardo Morim](https://www.linkedin.com/in/ricardo-morim-208368251/)

---

⭐ If this project helped you, please consider giving it a star!
