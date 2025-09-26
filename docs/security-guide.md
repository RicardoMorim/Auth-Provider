# Security Guide

This guide covers security best practices and considerations when using the Ricardo Auth Spring Boot Starter.

---

> **Major Security Enhancements in v4.0.0:**
> - **Cookie-Only Authentication:** Exclusive use of secure HTTP-only cookies for maximum XSS protection
> - **Enhanced CORS:** Comprehensive CORS configuration with credentials support
> - **Password Reset System:** OWASP-compliant password reset with email integration
> - **Domain Events:** Complete audit trail with event publishing for security monitoring
> - **Advanced Security:** Enhanced input validation, sanitization, and security headers
> - **OpenAPI Documentation:** Complete Swagger integration with security schemes

## Security Overview

The Ricardo Auth Starter implements comprehensive security mechanisms:

- **Cookie-Only Authentication**: Secure HTTP-only cookies with configurable security flags
- **Enhanced CORS**: Comprehensive cross-origin configuration with credentials support
- **UUID Primary Keys**: Enhanced security and scalability with UUID-based IDs
- **Password Encryption**: BCrypt hashing with secure salts
- **Role-Based Access Control**: Fine-grained permissions with full role management API
- **Input Validation & Sanitization**: Advanced protection against injection attacks
- **CSRF Protection**: Cross-Site Request Forgery protection with token-based validation
- **Password Reset System**: OWASP-compliant password reset with email integration
- **Domain Events**: Comprehensive audit trail for security monitoring
- **Rate Limiting**: Protection against brute-force and abuse attacks
- **Token Blocklist**: Instant token revocation capabilities
- **HTTPS Enforcement**: Automatic HTTPS redirection in production

## Want to make the value of a property not exposed in the properties?

### Option 1: Create a environment variable

1. Open the terminal
2. Set the variable
    - On Linux/macOS:
      ```bash
      export RICARDO_AUTH_POSTGRESQL_PASS=your_secure_password
      ```
    - On Windows:
      ```cmd
      set RICARDO_AUTH_POSTGRESQL_PASS=your_secure_password
      ```
3. Reference it in your application.yml:

```yml
auth:
  password:
    password: ${POSTGRE_SQL_PASS}
```

### Option 2: Use Dotenv

1. Create a `.env` file in your project root
2. Add your sensitive properties:
   ```
   RICARDO_AUTH_POSTGRESQL_PASS=your_secure_password
   ```
3. Load the `.env` file in a bean that starts before the other beans:
   ```java
   @Configuration

public class EarlyPropertyInjectionConfig {

      @Bean
      public static BeanFactoryPostProcessor injectPostgreSqlPassword() {
          return beanFactory -> {
              // Get the AuthProperties bean definition
              var beanDefinition = beanFactory.getBeanDefinition("authProperties");

              // Add a custom initializer to inject the password
              beanDefinition.setInstanceSupplier(() -> {
                  AuthProperties props = new AuthProperties();

                  // Inject the password from environment variable
                  String envPassword = System.getenv("POSTGRE_SQL_PASS");
                  if (envPassword != null) {
                      props.getPassword().setPassword(envPassword);
                  }

                  return props;
              });
          };
      }

}

```

## Cookie-Based Authentication Security

### Overview

Starting with v4.0.0, the Ricardo Auth Starter exclusively uses secure HTTP-only cookies for authentication, providing maximum protection against XSS attacks and improving overall security posture.

### Cookie Security Features

**HTTP-Only Cookies:**
- Prevents JavaScript access to tokens, eliminating XSS token theft
- Automatically handled by browsers for authentication
- Secure transmission only over HTTPS in production

**Security Flags:**
```yaml
ricardo:
  auth:
    cookies:
      access:
        secure: true        # HTTPS only
        http-only: true     # No JavaScript access
        same-site: Strict   # CSRF protection
        path: /             # Scope to entire application
        max-age: 900        # 15 minutes
      refresh:
        secure: true
        http-only: true
        same-site: Strict
        path: /api/auth/refresh  # Scope to refresh endpoint only
        max-age: 604800     # 7 days
```

### CORS Configuration for Cookie Authentication

**Backend Configuration:**

```yaml
ricardo:
  auth:
    cors:
      allowed-origins: ["https://yourdomain.com", "https://app.yourdomain.com"]
      allowed-methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
      allowed-headers: ["*"]
      allow-credentials: true  # Required for cookies
      max-age: 3600
```

**Frontend Integration:**

```javascript
// Ensure cookies are sent with all requests
fetch('/api/auth/me', {
  credentials: 'include'  // Always include cookies
});

// Axios configuration
axios.defaults.withCredentials = true;

// jQuery configuration
$.ajaxSetup({
  xhrFields: {
    withCredentials: true
  }
});
```

### HTTPS Requirements

**Production Security:**

- HTTPS is mandatory for secure cookies in production
- Automatic HTTPS redirection enabled by default
- SSL/TLS certificates required

**Development Configuration:**

```yaml
ricardo:
  auth:
    redirect-https: false  # Disable for development only
    cookies:
      access:
        secure: false      # Allow HTTP in development
      refresh:
        secure: false
```

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
random.

nextBytes(bytes);

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

| Security Level    | Recommended Expiration | Use Case                |
|-------------------|------------------------|-------------------------|
| High Security     | 15-60 minutes          | Banking, financial apps |
| Standard Security | 1-8 hours              | Business applications   |
| Low Security      | 24 hours - 7 days      | Social apps, blogs      |

```yaml
ricardo:
  auth:
    jwt:
      expiration: 3600000  # 1 hour for high security
```

### Token Storage (Client-Side)

**Recommended approach:**

- **HttpOnly Cookies** (Most Secure, now default)
   ```javascript
   // Automatically handled by browser, immune to XSS
   // Tokens are set as HttpOnly cookies by the backend
   // Frontend must send credentials (cookies) with each request
   fetch('/api/auth/me', { credentials: 'include' });
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

The Ricardo Auth Starter includes a comprehensive password policy system that enforces configurable password
requirements to enhance security.

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

## Password Reset Security

### OWASP-Compliant Implementation

The Ricardo Auth Starter implements a secure password reset system following OWASP guidelines:

**Security Features:**

- **Time-Limited Tokens**: Reset tokens expire after configurable time period
- **Cryptographically Secure Tokens**: Uses SecureRandom for token generation
- **Rate Limiting**: Prevents password reset abuse and enumeration attacks
- **Email Verification**: Requires access to user's email account
- **Single-Use Tokens**: Tokens are invalidated after use
- **Audit Trail**: Complete logging via domain events

### Configuration

```yaml
ricardo:
  auth:
    password-reset:
      enabled: true
      token-expiration: 3600000    # 1 hour (recommended)
      max-attempts: 3              # Per user per time window
      cleanup-interval: 3600000    # Clean expired tokens hourly
    email:
      enabled: true
      from: "noreply@yourdomain.com"
      reset-url-template: "https://yourdomain.com/reset-password?token={token}"
```

### Security Best Practices

**Token Security:**

- **Short Expiration**: 15-60 minutes maximum
- **Strong Randomness**: 256-bit cryptographically secure tokens
- **Single Use**: Tokens invalidated immediately after use
- **Database Storage**: Hashed token storage (never plain text)

**Rate Limiting:**

```yaml
ricardo:
  auth:
    rate-limiter:
      enabled: true
      max-requests: 3      # Max reset requests per hour
      time-window-ms: 3600000
```

**Email Security:**

- **HTTPS Links**: Always use HTTPS for reset URLs
- **Clear Instructions**: Include security warnings in emails
- **Branded Templates**: Use recognizable email templates
- **SPF/DKIM**: Configure email authentication

### Frontend Integration

**Secure Reset Flow:**

```javascript
// 1. Request password reset
const requestReset = async (email) => {
  const response = await fetch('/api/auth/password-reset/request', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
    credentials: 'include'
  });
  
  if (response.ok) {
    // Show success message (don't reveal if email exists)
    showMessage('If the email exists, a reset link has been sent.');
  }
};

// 2. Confirm password reset
const confirmReset = async (token, newPassword) => {
  const response = await fetch('/api/auth/password-reset/confirm', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, newPassword }),
    credentials: 'include'
  });
  
  if (response.ok) {
    // Redirect to login
    window.location.href = '/login';
  }
};
```

### Monitoring and Alerting

**Security Monitoring:**

- Track password reset request patterns
- Monitor for enumeration attempts
- Alert on unusual reset volumes
- Log all reset activities via domain events

**Metrics to Track:**

- Reset requests per user/IP
- Token usage patterns
- Failed reset attempts
- Email delivery success rates

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

- The starter now supports a `redirect-https` property to force HTTPS in production.
- Secure cookies (`Secure`, `SameSite`, `HttpOnly`) are used for all tokens by default.
- If using cookies, HTTPS is required for them to be sent by browsers.
- **The Authorization header is deprecated for authentication. Use secure cookies for all authentication flows.**

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

### Rate Limiting & Blocklist

### Rate Limiting

- The API implements rate limiting (memory or Redis) to prevent abuse and brute-force.
- Configure via `ricardo.auth.rate-limiter`.
- Implementations: `memory` (default) and `redis`.
- Example:

```yaml
ricardo:
  auth:
    rate-limiter:
      enabled: true
      type: redis  # or memory
      max-requests: 100
      time-window-ms: 60000
```

- If the limit is exceeded, HTTP 429 is returned.

### Token Blocklist (Revocation)

- Tokens can be revoked instantly (logout, admin, etc).
- Blocklist implemented in memory or Redis.
- Revocation endpoint: `/api/auth/revoke` (ADMIN, accepts access or refresh token).
- Example usage:

```bash
curl -X POST http://localhost:8080/api/auth/revoke \
  -H "Content-Type: application/json" \
  --cookie "access_token=<ADMIN_TOKEN>" \
  -d '{"token": "TOKEN_TO_REVOKE"}'
```

- Revoked tokens are rejected immediately.

> **Breaking change v2.0.0:**
> - Authentication cookies now use secure flags (`HttpOnly`, `Secure`, `SameSite`) by default. HTTPS is required for
    production.
> - Blocklist and rate limiting are enabled by default.
> - Revocation endpoint `/api/auth/revoke` was added and requires ADMIN permission.
> - The Authorization header is deprecated for authentication (except for legacy user endpoints). Use secure cookies for
    all authentication flows.

## CSRF Protection

### Overview

**NEW in v3.0.0**: The Ricardo Auth Starter now includes built-in Cross-Site Request Forgery (CSRF) protection to
prevent malicious websites from performing unauthorized actions on behalf of authenticated users.

### How CSRF Protection Works

CSRF protection in Ricardo Auth uses the **Synchronizer Token Pattern**:

1. **Token Generation**: The server generates a unique CSRF token for each session
2. **Token Storage**: The token is stored in a cookie named `XSRF-TOKEN` (readable by JavaScript)
3. **Token Validation**: All state-changing requests must include the CSRF token
4. **Token Verification**: The server validates the token matches the expected value

### Configuration

CSRF protection is enabled by default and automatically configured:

```java
// Automatically configured by SecurityConfig
.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    .ignoringRequestMatchers(PUBLIC_ENDPOINTS)
)
```

**Key Configuration Details:**

- Uses `CookieCsrfTokenRepository.withHttpOnlyFalse()` to allow JavaScript access
- Public endpoints (`/api/auth/login`, `/api/users/create`) are exempt
- All other authenticated endpoints require CSRF tokens

### Endpoints and CSRF Requirements

#### Exempt from CSRF Protection

- `POST /api/auth/login` - Public authentication endpoint
- `POST /api/users/create` - Public user registration endpoint

#### Require CSRF Protection

- `POST /api/auth/refresh` - Token refresh
- `POST /api/auth/revoke` - Token revocation (ADMIN)
- `PUT /api/users/update/{id}` - User updates
- `DELETE /api/users/delete/{id}` - User deletion
- All other authenticated endpoints

### Frontend Integration

#### JavaScript/Fetch Implementation

```javascript
// Utility function to get CSRF token from cookie
function getCsrfToken() {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'XSRF-TOKEN') {
            return decodeURIComponent(value);
        }
    }
    return null;
}

// Include CSRF token in authenticated requests
fetch('/api/auth/refresh', {
    method: 'POST',
    credentials: 'include', // Include cookies
    headers: {
        'Content-Type': 'application/json',
        'X-XSRF-TOKEN': getCsrfToken() // CSRF token
    }
});
```

#### Axios Configuration

```javascript
import axios from 'axios';

// Create axios instance with automatic CSRF token handling
const api = axios.create({
    withCredentials: true // Include cookies
});

// Add request interceptor for CSRF token
api.interceptors.request.use(config => {
    // Only add CSRF token for state-changing methods
    if (['post', 'put', 'delete', 'patch'].includes(config.method.toLowerCase())) {
        const token = getCsrfToken();
        if (token) {
            config.headers['X-XSRF-TOKEN'] = token;
        }
    }
    return config;
});

// Usage
api.post('/api/auth/refresh'); // CSRF token automatically included
```

#### jQuery Configuration

```javascript
// Global AJAX setup for CSRF tokens
$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        // Add CSRF token for state-changing requests
        if (settings.type === 'POST' || settings.type === 'PUT' || 
            settings.type === 'DELETE' || settings.type === 'PATCH') {
            const token = getCsrfToken();
            if (token) {
                xhr.setRequestHeader('X-XSRF-TOKEN', token);
            }
        }
    }
});
```

#### React Hook Example

```javascript
import { useState, useEffect } from 'react';

// Custom hook for CSRF token management
function useCsrfToken() {
    const [csrfToken, setCsrfToken] = useState(null);

    useEffect(() => {
        const token = getCsrfToken();
        setCsrfToken(token);
    }, []);

    return csrfToken;
}

// Usage in component
function MyComponent() {
    const csrfToken = useCsrfToken();

    const handleRefresh = async () => {
        if (!csrfToken) return;

        const response = await fetch('/api/auth/refresh', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'X-XSRF-TOKEN': csrfToken
            }
        });
    };

    return <button onClick={handleRefresh}>Refresh Token</button>;
}
```

### Error Handling

When CSRF protection is violated, the server returns a 403 Forbidden response:

```json
{
  "error": "Forbidden",
  "message": "CSRF token missing or invalid",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/auth/refresh"
}
```

**Common CSRF Error Scenarios:**

- Missing `X-XSRF-TOKEN` header
- Invalid or expired CSRF token
- Token mismatch between cookie and header
- Attempting to use form parameter instead of header

### Security Benefits

1. **Prevents CSRF Attacks**: Blocks malicious sites from performing actions as authenticated users
2. **Stateless Protection**: Works with JWT-based stateless authentication
3. **Flexible Implementation**: Supports both header and form parameter tokens
4. **Automatic Token Rotation**: Tokens are automatically refreshed as needed

### Best Practices

#### Development

```javascript
// Always check for CSRF token before making requests
const csrfToken = getCsrfToken();
if (!csrfToken) {
    console.warn('CSRF token not found - request may fail');
}
```

#### Production

- Ensure HTTPS is enabled (required for secure cookies)
- Monitor CSRF error rates in application logs
- Implement proper error handling for CSRF failures
- Use `SameSite=Strict` cookies when possible for additional protection

#### Testing

```javascript
// Test CSRF protection in your test suite
test('should reject requests without CSRF token', async () => {
    const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        credentials: 'include'
        // No CSRF token header
    });
    
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({
        error: 'Forbidden',
        message: 'CSRF token missing or invalid'
    });
});
```

### Troubleshooting

#### Common Issues

**1. "CSRF token missing" errors**

- **Cause**: Frontend not including `X-XSRF-TOKEN` header
- **Solution**: Ensure CSRF token is read from cookie and included in headers

**2. "Invalid CSRF token" errors**

- **Cause**: Token mismatch or expiration
- **Solution**: Refresh the page to get a new token

**3. CSRF token not found in cookies**

- **Cause**: Not making an initial request to get the token
- **Solution**: Make a GET request to any authenticated endpoint first

#### Debug Mode

Enable CSRF debugging:

```yaml
logging:
  level:
    org.springframework.security.web.csrf: DEBUG
```

This will log CSRF token generation, validation, and failures.

### Customization

#### Custom CSRF Token Repository

```java
@Configuration
public class CustomCsrfConfig {
    
    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        repository.setCookieName("MY_CSRF_TOKEN"); // Custom cookie name
        repository.setHeaderName("X-MY-CSRF-TOKEN"); // Custom header name
        repository.setCookiePath("/api/"); // Restrict cookie path
        return repository;
    }
}
```

#### Disable CSRF for Specific Endpoints

```java
@Configuration
public class CustomSecurityConfig {
    
    @Bean
    public SecurityFilterChain customFilterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringRequestMatchers("/api/webhooks/**") // Disable for webhooks
            )
            .build();
    }
}
```

### Migration from Previous Versions

If upgrading from v2.x to v3.0.0:

1. **Update Frontend Code**: Add CSRF token handling to all authenticated requests
2. **Test Thoroughly**: Ensure all API calls include the CSRF token
3. **Monitor Logs**: Watch for CSRF-related errors during deployment
4. **Gradual Rollout**: Consider feature flags for gradual CSRF enforcement

**Migration Script Example:**

```javascript
// Before v3.0.0
fetch('/api/auth/refresh', {
    method: 'POST',
    credentials: 'include'
});

// After v3.0.0
fetch('/api/auth/refresh', {
    method: 'POST',
    credentials: 'include',
    headers: {
        'X-XSRF-TOKEN': getCsrfToken() // Add this line
    }
});
```
