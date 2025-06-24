# Troubleshooting Guide

This guide helps you diagnose and resolve common issues when using the Ricardo Auth Spring Boot Starter.

## Common Issues

### 1. Application Fails to Start

#### JWT Secret Not Configured

**Error:**

```
***************************
APPLICATION FAILED TO START
***************************

Description:
Property 'ricardo.auth.jwt.secret' is required but not configured.

Action:
Configure the JWT secret in your application.yml or set the RICARDO_AUTH_JWT_SECRET environment variable.
```

**Solution:**

```yaml
ricardo:
  auth:
    jwt:
      secret: "your-256-bit-secret-key-here"
```

Or set environment variable:

```bash
export RICARDO_AUTH_JWT_SECRET="your-256-bit-secret-key-here"
```

#### Missing JPA Dependencies

**Error:**

```
***************************
APPLICATION FAILED TO START
***************************

Description:
Failed to configure a DataSource: 'url' attribute is not specified and no embedded datasource could be configured.

Action:
Consider the following:
    If you want an embedded database (H2, HSQL or Derby), please put it on the classpath.
    If you have database settings to be loaded from a particular profile you may need to activate it (no profiles are currently active).
```

**Solution:**
Add JPA and database dependencies to your `pom.xml`:

```xml

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>

        <!-- For development -->
<dependency>
<groupId>com.h2database</groupId>
<artifactId>h2</artifactId>
<scope>runtime</scope>
</dependency>
```

And configure datasource:

```yaml
spring:
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
    username: sa
    password: password
```

#### Bean Creation Errors

**Error:**

```
Error creating bean with name 'authAutoConfiguration': 
Injection of autowired dependencies failed
```

**Solution:**
Ensure all required dependencies are present and properly configured. Check for:

- Missing `@SpringBootApplication` annotation
- Conflicting bean definitions
- Circular dependencies

### 2. Authentication Issues

#### Login Always Returns 401 Unauthorized

**Possible Causes:**

1. **Incorrect credentials**
   ```bash
   # Verify user exists
   curl -X GET http://localhost:8080/api/users/exists/user@example.com
   ```

2. **Password encoding mismatch**
   ```java
   // Ensure consistent password encoding
   @Bean
   public PasswordEncoder passwordEncoder() {
       return new BCryptPasswordEncoder();
   }
   ```

3. **User not found in database**
   ```sql
   -- Check database directly
   SELECT * FROM users WHERE email = 'user@example.com';
   ```

4. **Wrong authentication provider**
   ```yaml
   # Enable debug logging
   logging:
     level:
       org.springframework.security: DEBUG
   ```

#### JWT Token Not Working

**Error:**

```json
{
  "error": "Unauthorized",
  "message": "JWT token is missing or invalid"
}
```

**Debug Steps:**

1. **Check token format**
   ```bash
   # Token should start with "Bearer "
   curl -H "Authorization: Bearer your-token-here" http://localhost:8080/api/auth/me
   ```

2. **Verify token expiration**
   ```javascript
   // Decode JWT token (client-side debugging)
   function decodeJWT(token) {
       const base64Url = token.split('.')[1];
       const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
       const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
           return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
       }).join(''));
       return JSON.parse(jsonPayload);
   }
   
   const payload = decodeJWT(token);
   console.log('Expires at:', new Date(payload.exp * 1000));
   ```

3. **Check JWT secret consistency**
   ```yaml
   # Ensure same secret across all services
   ricardo:
     auth:
       jwt:
         secret: ${JWT_SECRET}  # Same environment variable everywhere
   ```

#### CORS Issues

**Error:**

```
Access to fetch at 'http://localhost:8080/api/auth/login' from origin 'http://localhost:3000' 
has been blocked by CORS policy
```

**Solution:**

```yaml
spring:
  web:
    cors:
      allowed-origins: "http://localhost:3000"
      allowed-methods: "GET,POST,PUT,DELETE,OPTIONS"
      allowed-headers: "*"
      allow-credentials: true
```

Or configure programmatically:

```java

@Configuration
public class CorsConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

### 3. Database Issues

#### Table 'USER' doesn't exist

**Error:**

```
Table "USER" not found; SQL statement:
select user0_.id as id1_0_, user0_.email as email2_0_ from user user0_ where user0_.email=?
```

**Solutions:**

1. **Enable automatic schema creation (Development)**
   ```yaml
   spring:
     jpa:
       hibernate:
         ddl-auto: create-drop
   ```

2. **Create schema manually (Production)**
   ```sql
   CREATE TABLE users (
       id BIGINT AUTO_INCREMENT PRIMARY KEY,
       username VARCHAR(50) NOT NULL UNIQUE,
       email VARCHAR(255) NOT NULL UNIQUE,
       password VARCHAR(255) NOT NULL,
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
   );
   
   CREATE TABLE user_roles (
       user_id BIGINT,
       role VARCHAR(50),
       PRIMARY KEY (user_id, role),
       FOREIGN KEY (user_id) REFERENCES users(id)
   );
   ```

3. **Use migration tools (Recommended)**
   ```xml
   <!-- Add Flyway dependency -->
   <dependency>
       <groupId>org.flywaydb</groupId>
       <artifactId>flyway-core</artifactId>
   </dependency>
   ```

#### Connection Pool Issues

**Error:**

```
Connection is not available, request timed out after 30000ms.
```

**Solution:**

```yaml
spring:
  datasource:
    hikari:
      maximum-pool-size: 20
      minimum-idle: 5
      connection-timeout: 30000
      idle-timeout: 600000
      max-lifetime: 1800000
```

### 4. Testing Issues

#### Tests Fail with Bean Creation Errors

**Error:**

```
No qualifying bean of type 'javax.sql.DataSource' available
```

**Solution:**

```java

@SpringBootTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = {
        "ricardo.auth.jwt.secret=test-secret-key-for-testing-purposes-only",
        "spring.datasource.url=jdbc:h2:mem:testdb",
        "spring.jpa.hibernate.ddl-auto=create-drop"
})
class AuthIntegrationTest {
    // Test code
}
```

#### MockMvc Authentication Issues

**Problem:** Can't authenticate in tests

**Solution:**

```java

@Test
@WithMockUser(roles = "USER")
public void testProtectedEndpoint() throws Exception {
    mockMvc.perform(get("/api/auth/me"))
            .andExpect(status().isOk());
}

// Or with custom user
@Test
public void testWithCustomUser() throws Exception {
    String token = generateTestToken("test@example.com", "USER");

    mockMvc.perform(get("/api/auth/me")
                    .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk());
}

private String generateTestToken(String email, String role) {
    Collection<GrantedAuthority> authorities =
            Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role));
    return jwtService.generateToken(email, authorities);
}
```

### 5. Performance Issues

#### Slow Authentication Responses

**Symptoms:**

- Login takes > 2 seconds
- High CPU usage during authentication

**Diagnosis:**

```yaml
# Enable performance logging
logging:
  level:
    org.springframework.security: DEBUG
    org.hibernate.SQL: DEBUG
    org.hibernate.type: TRACE
```

**Solutions:**

1. **Optimize password encoding**
   ```java
   @Bean
   public PasswordEncoder passwordEncoder() {
       // Reduce rounds for better performance (security trade-off)
       return new BCryptPasswordEncoder(10);
   }
   ```

2. **Database indexing**
   ```sql
   CREATE INDEX idx_users_email ON users(email);
   CREATE INDEX idx_users_username ON users(username);
   ```

3. **Connection pooling**
   ```yaml
   spring:
     datasource:
       hikari:
         maximum-pool-size: 20
         minimum-idle: 5
   ```

#### Memory Leaks

**Symptoms:**

- Increasing memory usage over time
- OutOfMemoryError

**Solutions:**

1. **Check token storage**
   ```java
   // Avoid storing tokens in static collections
   // Use proper session management
   ```

2. **Database connection management**
   ```yaml
   spring:
     datasource:
       hikari:
         leak-detection-threshold: 60000
   ```

### 6. Production Issues

#### SSL/TLS Certificate Issues

**Error:**

```
SSL handshake failed: certificate verification failed
```

**Solutions:**

1. **Check certificate validity**
   ```bash
   openssl s_client -connect yourdomain.com:443 -servername yourdomain.com
   ```

2. **Update certificate store**
   ```bash
   keytool -import -trustcacerts -alias myserver -file server.crt -keystore $JAVA_HOME/jre/lib/security/cacerts
   ```

#### Load Balancer Issues

**Problem:** Sessions not persisting across servers

**Solution:**

```yaml
# Use stateless JWT authentication
ricardo:
  auth:
    jwt:
      expiration: 3600000  # Shorter expiration for load balanced environments

# Configure sticky sessions (if needed)
server:
  servlet:
    session:
      cookie:
        name: JSESSIONID
        path: /
        http-only: true
        secure: true
```

## Debugging Tools

### 1. Enable Debug Logging

```yaml
logging:
  level:
    root: INFO
    com.ricardo.auth: DEBUG
    org.springframework.security: DEBUG
    org.springframework.web: DEBUG
    org.hibernate.SQL: DEBUG
    org.hibernate.type.descriptor.sql.BasicBinder: TRACE
```

### 2. Health Check Endpoints

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,beans,env
  endpoint:
    health:
      show-details: always
```

Access health information:

```bash
curl http://localhost:8080/actuator/health
curl http://localhost:8080/actuator/beans
curl http://localhost:8080/actuator/env
```

### 3. JWT Token Decoder

```javascript
// Browser console debugging
function debugJWT(token) {
    try {
        const parts = token.split('.');
        const header = JSON.parse(atob(parts[0]));
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

        console.log('Header:', header);
        console.log('Payload:', payload);
        console.log('Issued:', new Date(payload.iat * 1000));
        console.log('Expires:', new Date(payload.exp * 1000));
        console.log('Is Expired:', Date.now() > payload.exp * 1000);
    } catch (e) {
        console.error('Invalid JWT token:', e);
    }
}

// Usage
debugJWT('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');
```

### 4. Database Query Debugging

```sql
-- Check user existence
SELECT id, username, email, created_at
FROM users
WHERE email = 'user@example.com';

-- Check user roles
SELECT u.email, ur.role
FROM users u
         LEFT JOIN user_roles ur ON u.id = ur.user_id
WHERE u.email = 'user@example.com';

-- Check password hash
SELECT email, password
FROM users
WHERE email = 'user@example.com';
```

### 5. Network Debugging

```bash
# Test API endpoints
curl -v -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}'

# Test with token
curl -v -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8080/api/auth/me

# Test CORS preflight
curl -v -X OPTIONS http://localhost:8080/api/auth/login \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type"
```

## Performance Monitoring

### Application Metrics

```yaml
# Enable metrics
management:
  endpoints:
    web:
      exposure:
        include: metrics,prometheus
  metrics:
    export:
      prometheus:
        enabled: true
```

### Custom Metrics

```java

@Component
public class AuthMetrics {

    private final Counter loginAttempts;
    private final Counter successfulLogins;
    private final Timer loginDuration;

    public AuthMetrics(MeterRegistry meterRegistry) {
        this.loginAttempts = Counter.builder("auth.login.attempts")
                .description("Total login attempts")
                .register(meterRegistry);

        this.successfulLogins = Counter.builder("auth.login.success")
                .description("Successful logins")
                .register(meterRegistry);

        this.loginDuration = Timer.builder("auth.login.duration")
                .description("Login duration")
                .register(meterRegistry);
    }

    public void recordLoginAttempt() {
        loginAttempts.increment();
    }

    public void recordSuccessfulLogin() {
        successfulLogins.increment();
    }

    public Timer.Sample startLoginTimer() {
        return Timer.start();
    }
}
```

## Getting Help

### 1. Check Documentation

- [Configuration Guide](configuration-guide.md)
- [API Reference](api-reference.md)
- [Security Guide](security-guide.md)

### 2. Enable Verbose Logging

```yaml
logging:
  level:
    com.ricardo.auth: TRACE
    org.springframework.security: DEBUG
```

### 3. Create Minimal Reproduction

When reporting issues, create a minimal example that reproduces the problem:

```java

@SpringBootApplication
public class MinimalReproduction {
    public static void main(String[] args) {
        SpringApplication.run(MinimalReproduction.class, args);
    }
}
```

### 4. Community Support

- [GitHub Issues](https://github.com/RicardoMorim/Auth-Provider/issues)
- [Stack Overflow](https://stackoverflow.com/questions/tagged/ricardo-auth-starter)

### 5. Version Compatibility

Ensure you're using compatible versions:

| Spring Boot | Ricardo Auth Starter | Java |
|-------------|----------------------|------|
| 3.5.x       | 1.0.0                | 21+  |

Remember to always check the changelog and migration guides when upgrading versions.
