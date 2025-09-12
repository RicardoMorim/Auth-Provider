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

### From Maven Central

Add the following dependency to your `pom.xml`:

```xml

<dependency>
    <groupId>io.github.ricardomorim</groupId>
    <artifactId>auth-spring-boot-starter</artifactId>
    <version>{Latest version release}</version>
</dependency>
```

### From GitHub Packages

1. Add the GitHub Packages repository to your `pom.xml`:

```xml

<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/RicardoMorim/Auth-Provider</url>
    </repository>
</repositories>
```

2. Configure authentication in your `~/.m2/settings.xml`:

```xml

<servers>
    <server>
        <id>github</id>
        <username>YOUR_GITHUB_USERNAME</username>
        <password>YOUR_GITHUB_TOKEN</password>
    </server>
</servers>
```

3. Add the dependency:

```xml

<dependency>
    <groupId>io.github.ricardomorim</groupId>
    <artifactId>auth-spring-boot-starter</artifactId>
    <version>{latest version release}</version>
</dependency>
```

## 🚨 Breaking Changes in v4.0.0

**Cookie-Only Authentication:** Authentication now exclusively uses secure HTTP-only cookies instead of Bearer tokens.

**What Changed:**
- **Cookie Authentication:** All endpoints now use secure HTTP-only cookies (`access_token`, `refresh_token`)
- **No More Bearer Tokens:** Authorization header authentication has been removed for security
- **HTTPS Required:** Secure cookies require HTTPS in production environments
- **Enhanced CORS:** Comprehensive CORS configuration with credentials support
- **OpenAPI Documentation:** Complete Swagger/OpenAPI integration with cookie authentication
- **Password Reset System:** OWASP-compliant password reset with email integration
- **Role Management API:** Full CRUD operations for roles with proper authorization
- **Domain Events:** Comprehensive audit trail with domain event publishing
- **Enhanced Security:** Rate limiting, input validation, and sanitization improvements

**What You Need to Update:**
- **Frontend:** Remove Authorization headers, ensure cookies are sent with requests
- **Configuration:** Add CORS configuration for your frontend domains
- **HTTPS:** Configure SSL/TLS for production environments
- **Email:** Configure email settings for password reset functionality

**Migration Guide:** See [Security Guide](docs/security-guide.md) and [Configuration Guide](docs/configuration/) for detailed migration steps.

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
      allowed-origins: ["https://yourdomain.com"]
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

## 📊 Monitoring and Health

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
