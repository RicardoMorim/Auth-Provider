# Security Guide

This guide covers security best practices and considerations when using the Ricardo Auth Spring Boot Starter.

## Security Overview

The Ricardo Auth Starter implements several security mechanisms:

- **JWT Token Authentication**: Stateless authentication using JSON Web Tokens
- **Password Encryption**: BCrypt hashing with secure salts
- **Role-Based Access Control**: Fine-grained permissions based on user roles
- **Input Validation**: Protection against malicious input
- **CORS Protection**: Cross-Origin Resource Sharing controls
- **SQL Injection Prevention**: JPA/Hibernate protection

## JWT Security

### Token Generation

JWT tokens are signed using HMAC SHA-256 with your secret key:

```java
// The starter automatically handles token generation
String token = jwtService.generateToken(username, authorities);
```

### Secret Key Security

**Critical: Your JWT secret key is the cornerstone of security.**

#### Requirements

- **Minimum length**: 256 bits (32 characters)
- **Randomness**: Cryptographically secure random generation
- **Uniqueness**: Different for each environment
- **Secrecy**: Never commit to version control

#### Generating Secure Secrets

**OpenSSL (Recommended):**
```bash
openssl rand -base64 32
```

**Node.js:**
```javascript
require('crypto').randomBytes(32).toString('base64')
```

**Python:**
```python
import secrets, base64
base64.b64encode(secrets.token_bytes(32)).decode()
```

**Java:**
```java
import java.security.SecureRandom;
import java.util.Base64;

SecureRandom random = new SecureRandom();
byte[] bytes = new byte[32];
random.nextBytes(bytes);
String secret = Base64.getEncoder().encodeToString(bytes);
```

#### Secret Rotation

Rotate your JWT secret regularly:

1. **Generate a new secret**
2. **Update configuration** with the new secret
3. **Deploy the update**
4. **All existing tokens will be invalidated** (users need to re-login)

### Token Expiration

Configure appropriate token expiration based on your security requirements:

| Security Level | Recommended Expiration | Use Case |
|----------------|----------------------|----------|
| High Security | 15-60 minutes | Banking, financial apps |
| Standard Security | 1-8 hours | Business applications |
| Low Security | 24 hours - 7 days | Social apps, blogs |

```yaml
ricardo:
  auth:
    jwt:
      expiration: 3600000  # 1 hour for high security
```

### Token Storage (Client-Side)

**Recommended approaches:**

1. **HttpOnly Cookies** (Most Secure)
   ```javascript
   // Automatically handled by browser, immune to XSS
   // Configure your server to use HttpOnly cookies
   ```

2. **Memory Storage** (Secure but loses on refresh)
   ```javascript
   // Store in component state or Redux store
   // Token lost on page refresh
   ```

3. **SessionStorage** (Acceptable)
   ```javascript
   sessionStorage.setItem('token', token);
   // Lost when tab closes
   ```

**Avoid:**
- LocalStorage (vulnerable to XSS)
- URL parameters (logged in server logs)
- Unencrypted cookies

## Password Security

### Password Hashing

The starter uses BCrypt with automatic salt generation:

```java
// Passwords are automatically hashed
Password password = Password.valueOf(plainTextPassword, passwordEncoder);
```

### Password Requirements

Implement strong password policies in your frontend:

```javascript
function validatePassword(password) {
    const requirements = {
        minLength: password.length >= 8,
        hasUppercase: /[A-Z]/.test(password),
        hasLowercase: /[a-z]/.test(password),
        hasNumbers: /\d/.test(password),
        hasSpecialChar: /[!@#$%^&*(),.?":{}|<>]/.test(password)
    };
    
    return Object.values(requirements).every(req => req);
}
```

### Password Storage

**Never store passwords in plain text:**

✅ **Good:**
```java
// The starter handles this automatically
String hashedPassword = passwordEncoder.encode(plainTextPassword);
```

❌ **Bad:**
```java
// Never do this
String password = "plaintext"; // Stored in database
```

## Password Policy System

### Overview

The Ricardo Auth Starter includes a comprehensive password policy system that enforces configurable password requirements to enhance security.

### Password Requirements

#### Default Policy

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 10
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      prevent-common-passwords: true
```

#### Security Benefits

1. **Length Requirements**: Longer passwords exponentially increase brute-force difficulty
2. **Character Diversity**: Mixed character types prevent dictionary attacks
3. **Common Password Prevention**: Blocks easily guessable passwords
4. **Configurable Policies**: Adapt requirements to your security needs

### Implementation Details

#### Password Validation Process

1. **Length Check**: Validates minimum and maximum length
2. **Character Requirements**: Checks for required character types
3. **Common Password Check**: Compares against known weak passwords
4. **Custom Validation**: Extensible for additional rules

#### Built-in Common Passwords

The system includes 10,000+ common passwords including:
- Dictionary words
- Common patterns (123456, password, etc.)
- Keyboard patterns (qwerty, asdf, etc.)
- Name variations
- Date patterns

### Best Practices

#### Production Configuration

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 12              # Enterprise standard
      max-length: 64              # Prevent DoS via long passwords
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      special-characters: "!@#$%^&*()_+-=[]{}|;:,.<>?"
      prevent-common-passwords: true
```

#### User Experience Tips

1. **Clear Error Messages**: Specific feedback helps users create compliant passwords
2. **Password Strength Indicators**: Show real-time validation in frontend
3. **Password Generation**: Offer secure password generation
4. **Progressive Enhancement**: Start with basic requirements, increase gradually

### Compliance

The password policy system helps meet compliance requirements:

- **NIST 800-63B**: Supports length and complexity requirements
- **OWASP**: Follows password security guidelines
- **GDPR**: Implements "security by design" principles
- **SOC 2**: Supports access control requirements

### Monitoring

Track password policy effectiveness:

```yaml
logging:
  level:
    com.ricardo.auth.service.PasswordPolicy: INFO
```

Monitor these metrics:
- Password policy violation rates
- Common password attempt frequency
- Password strength distribution

## Role-Based Access Control (RBAC)

### Default Roles

The starter provides these roles:
- `USER`: Standard user permissions
- `ADMIN`: Administrative permissions

### Custom Roles

Extend the role system:

```java
public enum CustomRole implements Role {
    MANAGER("ROLE_MANAGER"),
    MODERATOR("ROLE_MODERATOR"),
    PREMIUM_USER("ROLE_PREMIUM_USER");
    
    private final String authority;
    
    CustomRole(String authority) {
        this.authority = authority;
    }
    
    @Override
    public String getAuthority() {
        return authority;
    }
}
```

### Method-Level Security

Secure individual methods:

```java
@RestController
public class SecureController {
    
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin-only")
    public ResponseEntity<String> adminEndpoint() {
        return ResponseEntity.ok("Admin content");
    }
    
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    @GetMapping("/user-content")
    public ResponseEntity<String> userEndpoint() {
        return ResponseEntity.ok("User content");
    }
    
    @PreAuthorize("@userSecurityService.isOwner(authentication.name, #userId)")
    @GetMapping("/users/{userId}/profile")
    public ResponseEntity<UserDTO> getUserProfile(@PathVariable Long userId) {
        // Only the user themselves can access their profile
        return ResponseEntity.ok(userService.getUserById(userId));
    }
}
```

### Custom Security Service

Implement complex authorization logic:

```java
@Service("userSecurityService")
public class UserSecurityService {
    
    private final UserService userService;
    
    public boolean isOwner(String email, Long userId) {
        try {
            User user = userService.getUserByEmail(email);
            return user.getId().equals(userId);
        } catch (Exception e) {
            return false;
        }
    }
    
    public boolean canEditUser(String email, Long targetUserId) {
        try {
            User currentUser = userService.getUserByEmail(email);
            
            // Admins can edit anyone
            if (currentUser.hasRole(AppRole.ADMIN)) {
                return true;
            }
            
            // Users can edit themselves
            return currentUser.getId().equals(targetUserId);
        } catch (Exception e) {
            return false;
        }
    }
}
```

## HTTPS and Transport Security

### Enable HTTPS

**Never run authentication in production without HTTPS.**

#### Spring Boot HTTPS Configuration

```yaml
server:
  port: 8443
  ssl:
    key-store: classpath:keystore.p12
    key-store-password: ${SSL_KEYSTORE_PASSWORD}
    key-store-type: PKCS12
    key-alias: tomcat
```

#### Let's Encrypt (Free SSL)

```bash
# Install Certbot
sudo apt install certbot

# Generate certificate
sudo certbot certonly --standalone -d yourdomain.com

# Configure Spring Boot to use the certificate
```

#### Reverse Proxy (Nginx)

```nginx
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## CORS Configuration

Configure CORS properly to prevent unauthorized cross-origin requests:

```yaml
spring:
  web:
    cors:
      allowed-origins: 
        - "https://yourdomain.com"
        - "https://app.yourdomain.com"
      allowed-methods: 
        - "GET"
        - "POST" 
        - "PUT"
        - "DELETE"
        - "OPTIONS"
      allowed-headers: 
        - "Authorization"
        - "Content-Type"
        - "X-Requested-With"
      allow-credentials: true
      max-age: 3600
```

**Security Notes:**
- Never use `*` for `allowed-origins` in production
- Only include necessary HTTP methods
- Be specific about allowed headers
- Use `allow-credentials: true` only when necessary

## Input Validation

### Request Validation

Always validate input data:

```java
@RestController
public class SecureUserController {
    
    @PostMapping("/users")
    public ResponseEntity<UserDTO> createUser(@Valid @RequestBody CreateUserRequestDTO request) {
        // @Valid annotation triggers validation
        // Custom validation in DTO:
    }
}

// DTO with validation
public class CreateUserRequestDTO {
    
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "Username can only contain letters, numbers, and underscores")
    private String username;
    
    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid")
    @Size(max = 255, message = "Email must not exceed 255 characters")
    private String email;
    
    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
    private String password;
}
```

### SQL Injection Prevention

The starter uses JPA/Hibernate, which provides automatic protection:

✅ **Safe (Parameterized queries):**
```java
@Query("SELECT u FROM User u WHERE u.email = :email")
Optional<User> findByEmail(@Param("email") String email);
```

❌ **Dangerous (String concatenation):**
```java
// Never do this - vulnerable to SQL injection
@Query("SELECT u FROM User u WHERE u.email = '" + email + "'")
```

## Security Headers

Add security headers to your responses:

```java
@Configuration
public class SecurityHeadersConfig {
    
    @Bean
    public FilterRegistrationBean<SecurityHeadersFilter> securityHeadersFilter() {
        FilterRegistrationBean<SecurityHeadersFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new SecurityHeadersFilter());
        registration.addUrlPatterns("/*");
        return registration;
    }
}

public class SecurityHeadersFilter implements Filter {
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        // Prevent XSS attacks
        httpResponse.setHeader("X-Content-Type-Options", "nosniff");
        httpResponse.setHeader("X-Frame-Options", "DENY");
        httpResponse.setHeader("X-XSS-Protection", "1; mode=block");
        
        // HTTPS enforcement
        httpResponse.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        
        // Content Security Policy
        httpResponse.setHeader("Content-Security-Policy", "default-src 'self'");
        
        chain.doFilter(request, response);
    }
}
```

## Monitoring and Auditing

### Security Logging

Enable security event logging:

```yaml
logging:
  level:
    org.springframework.security: INFO
    com.ricardo.auth: INFO
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
```

### Audit Events

Track important security events:

```java
@EventListener
public class SecurityAuditEventListener {
    
    private static final Logger logger = LoggerFactory.getLogger(SecurityAuditEventListener.class);
    
    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        logger.info("Successful authentication for user: {}", event.getAuthentication().getName());
    }
    
    @EventListener
    public void onAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        logger.warn("Failed authentication attempt for user: {}", 
                   event.getAuthentication().getName());
    }
}
```

### Rate Limiting

Implement rate limiting to prevent brute force attacks:

```java
@Component
public class RateLimitingFilter implements Filter {
    
    private final Map<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();
    private final Map<String, Long> requestTimes = new ConcurrentHashMap<>();
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String clientIP = getClientIP(httpRequest);
        
        if (isRateLimited(clientIP)) {
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            httpResponse.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            httpResponse.getWriter().write("Rate limit exceeded");
            return;
        }
        
        chain.doFilter(request, response);
    }
    
    private boolean isRateLimited(String clientIP) {
        long currentTime = System.currentTimeMillis();
        long windowStart = currentTime - TimeUnit.MINUTES.toMillis(1); // 1-minute window
        
        // Reset counter if window has expired
        Long lastRequestTime = requestTimes.get(clientIP);
        if (lastRequestTime == null || lastRequestTime < windowStart) {
            requestCounts.put(clientIP, new AtomicInteger(1));
            requestTimes.put(clientIP, currentTime);
            return false;
        }
        
        // Check if rate limit exceeded (e.g., 100 requests per minute)
        AtomicInteger count = requestCounts.get(clientIP);
        if (count.incrementAndGet() > 100) {
            return true;
        }
        
        return false;
    }
}
```

## Security Checklist

### Development
- [ ] Use strong JWT secret keys
- [ ] Set appropriate token expiration times
- [ ] Implement input validation
- [ ] Use HTTPS in development
- [ ] Enable security logging
- [ ] Test authentication flows

### Staging/Testing
- [ ] Test with realistic data volumes
- [ ] Perform security penetration testing
- [ ] Validate rate limiting
- [ ] Test token expiration handling
- [ ] Verify CORS configuration

### Production
- [ ] Use environment variables for secrets
- [ ] Enable HTTPS with valid certificates
- [ ] Configure proper CORS policies
- [ ] Set up monitoring and alerting
- [ ] Implement log aggregation
- [ ] Regular security updates
- [ ] Backup and recovery procedures

## Common Security Vulnerabilities

### 1. Weak JWT Secrets

❌ **Problem:**
```yaml
ricardo:
  auth:
    jwt:
      secret: "secret"  # Too short and predictable
```

✅ **Solution:**
```yaml
ricardo:
  auth:
    jwt:
      secret: ${RICARDO_AUTH_JWT_SECRET}  # Long, random, environment-specific
```

### 2. Token Storage in LocalStorage

❌ **Problem:**
```javascript
// Vulnerable to XSS attacks
localStorage.setItem('token', token);
```

✅ **Solution:**
```javascript
// Use HttpOnly cookies or sessionStorage
sessionStorage.setItem('token', token);
```

### 3. No HTTPS

❌ **Problem:**
```
http://myapp.com/api/auth/login  // Credentials sent in plain text
```

✅ **Solution:**
```
https://myapp.com/api/auth/login  // Encrypted transport
```

### 4. Overly Permissive CORS

❌ **Problem:**
```yaml
spring:
  web:
    cors:
      allowed-origins: "*"  # Allows any origin
```

✅ **Solution:**
```yaml
spring:
  web:
    cors:
      allowed-origins: "https://yourdomain.com"  # Specific origins only
```

### 5. Long Token Expiration

❌ **Problem:**
```yaml
ricardo:
  auth:
    jwt:
      expiration: 31536000000  # 1 year - too long
```

✅ **Solution:**
```yaml
ricardo:
  auth:
    jwt:
      expiration: 3600000  # 1 hour - appropriate for sensitive apps
```

## Security Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [JWT Security Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
