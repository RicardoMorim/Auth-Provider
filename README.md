# Ricardo Auth Spring Boot Starter

[![Maven Central](https://img.shields.io/maven-central/v/io.github.ricardomorim/auth-spring-boot-starter?color=blue&label=Maven%20Central)](https://central.sonatype.com/artifact/io.github.ricardomorim/auth-spring-boot-starter)
[![GitHub release](https://img.shields.io/github/release/RicardoMorim/Auth-Provider.svg)](https://github.com/RicardoMorim/Auth-Provider/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A **plug-and-play** Spring Boot starter that adds JWT authentication and user management to your application with minimal configuration required.

> 🚀 **Zero-configuration setup** - Just add the dependency and you're ready to go!  
> 🔐 **Production-ready security** - Built-in password policies, JWT tokens, and role-based access  
> 📚 **Complete documentation** - Comprehensive guides for setup, configuration, and deployment

## ✨ What You Get

**Authentication & Security**
- 🔑 JWT token generation, validation, and refresh
- 🛡️ Configurable password policies with strength validation
- 🔒 BCrypt password encryption
- 👥 Role-based access control (RBAC)
- 🚫 Protection against common weak passwords

**Ready-to-Use API Endpoints**
- `/api/auth/login` - User authentication
- `/api/auth/register` - User registration
- `/api/users/*` - Complete user management CRUD

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
    <version>1.1.0</version>
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
    <version>1.1.0</version>
</dependency>
```

## ⚡ Quick Start

> **Prerequisites:** Java 17+, Maven/Gradle, and an existing Spring Boot project

### Step 1: Add the Dependency

```xml
<dependency>
    <groupId>io.github.ricardomorim</groupId>
    <artifactId>auth-spring-boot-starter</artifactId>
    <version>1.1.0</version>
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

**Login to get JWT token:**
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass@123!"
  }'
```

**Use the token to access protected endpoints:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN_HERE" \
     http://localhost:8080/api/auth/me
```

🎉 **That's it!** Your Spring Boot app now has complete JWT authentication and user management.

> � **New to Ricardo Auth?** Check out our [5-minute Getting Started Guide](docs/getting-started.md)  
> �💡 **Need more control?** See the [Configuration Guide](docs/configuration-guide.md) for advanced options.

## 📖 Documentation

| Guide | Purpose | When to Use |
|-------|---------|-------------|
| **[Configuration Guide](docs/configuration-guide.md)** | Complete setup options | Customizing behavior |
| **[API Reference](docs/api-reference.md)** | All endpoints & examples | Frontend integration |
| **[Security Guide](docs/security-guide.md)** | Production security | Deploying safely |
| **[Examples](docs/examples.md)** | Real-world use cases | Learning patterns |
| **[Troubleshooting](docs/troubleshooting.md)** | Common issues & fixes | Debugging problems |

## 🔧 Configuration

### Application Properties

Configure the starter using `application.yml` or `application.properties`:

```yaml
ricardo:
  auth:
    enabled: true  # Enable/disable the entire auth module
    jwt:
      secret: "your-secret-key"  # Required: JWT signing secret
      expiration: 604800000      # Token expiration time in ms (default: 7 days)
    controllers:
      auth:
        enabled: true   # Enable/disable auth endpoints
      user:
        enabled: true   # Enable/disable user management endpoints
```

### Password Policy Configuration

Configure password requirements to enhance security:

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 10                    # Minimum password length
      max-length: 128                   # Maximum password length  
      require-uppercase: true           # Require uppercase letters
      require-lowercase: true           # Require lowercase letters
      require-digits: true              # Require numeric digits
      require-special-chars: true       # Require special characters
      special-characters: "!@#$%^&*"    # Allowed special characters
      prevent-common-passwords: true    # Block common passwords
      common-passwords-file: "/commonpasswords.txt"  # Custom password list
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
Authenticate a user and receive a JWT token.

**Request:**
```json
{
    "email": "user@example.com",
    "password": "password123"
}
```

**Response:**
```json
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### GET `/api/auth/me`
Get the currently authenticated user's information.

**Headers:**
```
Authorization: Bearer {token}
```

**Response:**
```json
{
    "username": "user@example.com",
    "authorities": ["ROLE_USER"]
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
    "id": 1,
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
    "id": 1,
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

## 🔐 Security

### Using JWT Tokens

Include the JWT token in the `Authorization` header:

```bash
curl -H "Authorization: Bearer your-jwt-token" \
     http://localhost:8080/api/auth/me
```

### Role-Based Access Control

The starter includes built-in roles:
- `USER`: Standard user role
- `ADMIN`: Administrative privileges

Users are automatically assigned the `USER` role upon creation.

### Password Security

Passwords are automatically encrypted using BCrypt with a secure salt.

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

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

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

---

⭐ If this project helped you, please consider giving it a star!
