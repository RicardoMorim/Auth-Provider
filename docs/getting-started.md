# Getting Started with Ricardo Auth

Welcome! This guide will have you up and running with Ricardo Auth in **5 minutes**.

## 🚀 What is Ricardo Auth?

Ricardo Auth is a **plug-and-play Spring Boot starter** that adds JWT authentication and user management to your application with zero configuration required.

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
    <version>1.1.0</version>
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

**Login to get JWT tokens:**
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
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

**Use the access token:**
```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE" \
     http://localhost:8080/api/auth/me
```

🎉 **Congratulations!** You now have a Spring Boot app with:
- ✅ User registration and login
- ✅ JWT access and refresh tokens
- ✅ Secure token refresh system
- ✅ Secure password policies
- ✅ Role-based access control
- ✅ Complete REST API

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

**Get Support:**
- 📖 [Documentation](docs/index.md) - Complete guides
- 🐛 [GitHub Issues](https://github.com/RicardoMorim/Auth-Provider/issues) - Report problems
- 💬 [Discussions](https://github.com/RicardoMorim/Auth-Provider/discussions) - Ask questions

---

⭐ **Found this helpful?** Give us a star on [GitHub](https://github.com/RicardoMorim/Auth-Provider)!
