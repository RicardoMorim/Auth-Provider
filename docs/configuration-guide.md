# Configuration Guide

This guide provides detailed information about configuring the Ricardo Auth Spring Boot Starter.

## Configuration Properties

### Complete Configuration Reference

```yaml
ricardo:
  auth:
    enabled: true                    # Enable/disable the entire auth module
    jwt:
      secret: "your-secret-key"      # JWT signing secret (REQUIRED)
      expiration: 604800000          # Token expiration in milliseconds (default: 7 days)
    controllers:
      auth:
        enabled: true                # Enable/disable authentication endpoints
      user:
        enabled: true                # Enable/disable user management endpoints
```

### Environment-Specific Configuration

#### Development
```yaml
ricardo:
  auth:
    jwt:
      secret: "dev-secret-key-make-it-long-enough-for-security"
      expiration: 86400000           # 1 day for development
    controllers:
      auth:
        enabled: true
      user:
        enabled: true

spring:
  jpa:
    hibernate:
      ddl-auto: create-drop          # Recreate schema on restart
    show-sql: true                   # Show SQL queries in logs
  h2:
    console:
      enabled: true                  # Enable H2 console for development
```

#### Production
```yaml
ricardo:
  auth:
    jwt:
      secret: ${RICARDO_AUTH_JWT_SECRET}  # Use environment variable
      expiration: 604800000               # 7 days
    controllers:
      auth:
        enabled: true
      user:
        enabled: true

spring:
  jpa:
    hibernate:
      ddl-auto: validate             # Validate schema without changes
    show-sql: false                  # Hide SQL in production logs
  
# Production database configuration
  datasource:
    url: ${DATABASE_URL}
    username: ${DATABASE_USERNAME}
    password: ${DATABASE_PASSWORD}
    hikari:
      maximum-pool-size: 20
      minimum-idle: 5
```

## Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `RICARDO_AUTH_JWT_SECRET` | JWT signing secret | `your-256-bit-secret-key` |

### Optional Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `RICARDO_AUTH_JWT_EXPIRATION` | Token expiration (ms) | `604800000` | `86400000` |
| `RICARDO_AUTH_ENABLED` | Enable auth module | `true` | `false` |
| `RICARDO_AUTH_CONTROLLERS_AUTH_ENABLED` | Enable auth endpoints | `true` | `false` |
| `RICARDO_AUTH_CONTROLLERS_USER_ENABLED` | Enable user endpoints | `true` | `false` |

### Setting Environment Variables

#### Linux/macOS
```bash
export RICARDO_AUTH_JWT_SECRET="your-very-secure-secret-key-here"
export RICARDO_AUTH_JWT_EXPIRATION="604800000"
```

#### Windows
```cmd
set RICARDO_AUTH_JWT_SECRET=your-very-secure-secret-key-here
set RICARDO_AUTH_JWT_EXPIRATION=604800000
```

#### Docker
```dockerfile
ENV RICARDO_AUTH_JWT_SECRET=your-very-secure-secret-key-here
ENV RICARDO_AUTH_JWT_EXPIRATION=604800000
```

#### Docker Compose
```yaml
version: '3.8'
services:
  app:
    image: your-app:latest
    environment:
      - RICARDO_AUTH_JWT_SECRET=your-very-secure-secret-key-here
      - RICARDO_AUTH_JWT_EXPIRATION=604800000
      - DATABASE_URL=jdbc:postgresql://db:5432/myapp
    depends_on:
      - db
  
  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=myapp
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=password
```

## JWT Configuration

### Secret Key Requirements

The JWT secret must be:
- At least 256 bits (32 characters) long
- Cryptographically secure
- Unique for each environment

#### Generating a Secure Secret

**Using OpenSSL:**
```bash
openssl rand -base64 32
```

**Using Node.js:**
```javascript
require('crypto').randomBytes(32).toString('base64')
```

**Using Python:**
```python
import secrets
import base64
base64.b64encode(secrets.token_bytes(32)).decode()
```

### Token Expiration

Configure token expiration based on your security requirements:

| Use Case | Recommended Expiration |
|----------|----------------------|
| High-security applications | 15-60 minutes |
| Standard web applications | 1-24 hours |
| Mobile applications | 1-7 days |
| Development/testing | 24 hours |

```yaml
ricardo:
  auth:
    jwt:
      expiration: 3600000    # 1 hour (3600000 ms)
      # expiration: 86400000   # 1 day (86400000 ms)
      # expiration: 604800000  # 7 days (604800000 ms)
```

## Database Configuration

### H2 (Development)
```yaml
spring:
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
    username: sa
    password: password
  jpa:
    database-platform: org.hibernate.dialect.H2Dialect
    hibernate:
      ddl-auto: create-drop
  h2:
    console:
      enabled: true
      path: /h2-console
```

### PostgreSQL (Production)
```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/auth_db
    driver-class-name: org.postgresql.Driver
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
  jpa:
    database-platform: org.hibernate.dialect.PostgreSQLDialect
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        format_sql: false
        show_sql: false
```

### MySQL (Production)
```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/auth_db?useSSL=false&serverTimezone=UTC
    driver-class-name: com.mysql.cj.jdbc.Driver
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
  jpa:
    database-platform: org.hibernate.dialect.MySQLDialect
    hibernate:
      ddl-auto: validate
```

## Security Configuration

### CORS Configuration
```yaml
spring:
  web:
    cors:
      allowed-origins: "http://localhost:3000,https://yourdomain.com"
      allowed-methods: "GET,POST,PUT,DELETE,OPTIONS"
      allowed-headers: "*"
      allow-credentials: true
```

### Actuator Security
```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
      base-path: /actuator
  endpoint:
    health:
      show-details: when-authorized
  security:
    enabled: true
```

## Logging Configuration

```yaml
logging:
  level:
    root: INFO
    com.ricardo.auth: DEBUG           # Auth starter debug logs
    org.springframework.security: DEBUG  # Spring Security debug logs
    org.springframework.web: DEBUG   # Web request debug logs
    org.hibernate.SQL: DEBUG         # SQL query logs
    org.hibernate.type: TRACE        # SQL parameter logs
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} - %msg%n"
    file: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
  file:
    name: logs/auth-app.log
```

## Profile-Based Configuration

### application.yml
```yaml
spring:
  profiles:
    active: dev

---
spring:
  config:
    activate:
      on-profile: dev

ricardo:
  auth:
    jwt:
      secret: "dev-secret-key-make-it-long-enough"
      expiration: 86400000

spring:
  datasource:
    url: jdbc:h2:mem:devdb
    driver-class-name: org.h2.Driver
  jpa:
    hibernate:
      ddl-auto: create-drop

---
spring:
  config:
    activate:
      on-profile: prod

ricardo:
  auth:
    jwt:
      secret: ${RICARDO_AUTH_JWT_SECRET}
      expiration: 604800000

spring:
  datasource:
    url: ${DATABASE_URL}
    username: ${DATABASE_USERNAME}
    password: ${DATABASE_PASSWORD}
  jpa:
    hibernate:
      ddl-auto: validate
```

## Configuration Validation

The starter validates configuration on startup:

### Required Configuration
- `ricardo.auth.jwt.secret` must be provided and non-empty
- Database configuration must be valid
- JPA dependencies must be available

### Common Validation Errors

#### Missing JWT Secret
```
***************************
APPLICATION FAILED TO START
***************************

Description:
Property 'ricardo.auth.jwt.secret' is required but not configured.

Action:
Configure the JWT secret in your application.yml or set the RICARDO_AUTH_JWT_SECRET environment variable.
```

#### Invalid Database Configuration
```
***************************
APPLICATION FAILED TO START
***************************

Description:
Failed to configure a DataSource: 'url' attribute is not specified

Action:
Configure a valid database connection in your application.yml
```

## Best Practices

1. **Never hardcode secrets** in configuration files
2. **Use environment variables** in production
3. **Rotate JWT secrets** regularly
4. **Use secure token expiration** times
5. **Enable HTTPS** in production
6. **Monitor token usage** with actuator endpoints
7. **Validate configuration** in CI/CD pipelines
8. **Use strong database passwords**
9. **Keep dependencies updated**
10. **Enable security logging** for auditing
