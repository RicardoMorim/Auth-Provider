# Authentication Issues

Resolve **login, token, and authentication problems** with Ricardo Auth quickly and effectively.

## 📋 Quick Navigation

- [Login Problems](#login-problems)
- [Token Issues](#token-issues)
- [User Registration Issues](#user-registration-issues)
- [Permission and Role Issues](#permission-and-role-issues)
- [CORS Issues](#cors-issues)
- [Session Problems](#session-problems)
- [Testing and Debugging](#testing-and-debugging)

## Login Problems

### Login Always Returns 401 Unauthorized

**❌ Symptoms:**
- Valid credentials return 401
- All login attempts fail
- "Bad credentials" error message

**🔍 Diagnostic Steps:**

**1. Verify User Exists:**
```bash
# Check if user exists in database
curl -X GET "http://localhost:8080/api/users/exists/test@example.com"
```

**2. Check Password Encoding:**
```java
// Debug password matching
@RestController
public class DebugController {
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @GetMapping("/debug/password")
    public String debugPassword(@RequestParam String raw, @RequestParam String encoded) {
        boolean matches = passwordEncoder.matches(raw, encoded);
        return "Password matches: " + matches;
    }
}
```

**3. Enable Authentication Debug Logging:**
```yaml
logging:
  level:
    org.springframework.security: DEBUG
    com.ricardo.auth: DEBUG
```

**✅ Common Solutions:**

**1. Password Encoding Mismatch:**
```java
// Ensure consistent password encoder
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(); // Same encoder used everywhere
}
```

**2. User Not Found in Database:**
```sql
-- Check users table directly
SELECT id, username, email, password FROM users WHERE email = 'test@example.com';
```

**3. Incorrect Login Endpoint:**
```bash
# ✅ Correct endpoint
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'

# ❌ Wrong endpoint
curl -X POST http://localhost:8080/login  # Missing /api/auth
```

**4. Case-Sensitive Email Issues:**
```java
// Ensure consistent email handling
@PrePersist
@PreUpdate
public void normalizeEmail() {
    if (this.email != null) {
        this.email = this.email.toLowerCase().trim();
    }
}
```

### Invalid Credentials Error

**❌ Error Message:**
```json
{
  "error": "Unauthorized",
  "message": "Bad credentials",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**✅ Solutions:**

**1. Check Request Format:**
```bash
# ✅ Correct JSON format
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'

# ❌ Wrong field names
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user@example.com",  # Should be "email"
    "password": "password123"
  }'
```

**2. Verify Password Policy Compliance:**
```bash
# Test with a simple password first
curl -X POST http://localhost:8080/api/users/create \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "SimplePass123!"
  }'
```

**3. Debug User Creation:**
```java
@RestController
public class DebugUserController {
    
    @PostMapping("/debug/create-user")
    public ResponseEntity<String> createDebugUser() {
        try {
            User user = new User(
                Username.valueOf("debuguser"),
                Email.valueOf("debug@example.com"),
                Password.valueOf("DebugPass123!", passwordEncoder)
            );
            user.addRole(AppRole.USER);
            User savedUser = userService.createUser(user);
            return ResponseEntity.ok("User created with ID: " + savedUser.getId());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }
}
```

## Token Issues

### JWT Token Not Working

**❌ Symptoms:**
- Token returns "Invalid token" error
- Protected endpoints return 401 with valid token
- Token appears valid but authentication fails

**🔍 Diagnostic Steps:**

**1. Verify Token Format:**
```bash
# Token should start with "Bearer "
curl -H "Authorization: Bearer your-token-here" \
     http://localhost:8080/api/auth/me

# ❌ Wrong format
curl -H "Authorization: your-token-here" \  # Missing "Bearer "
     http://localhost:8080/api/auth/me
```

**2. Check Token Expiration:**
```javascript
// Decode JWT token (client-side debugging)
function decodeJWT(token) {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
        atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join('')
    );
    return JSON.parse(jsonPayload);
}

const payload = decodeJWT(token);
console.log('Token expires at:', new Date(payload.exp * 1000));
console.log('Is expired:', Date.now() > payload.exp * 1000);
```

**3. Verify JWT Secret Consistency:**
```yaml
# Ensure same secret across all services/restarts
ricardo:
  auth:
    jwt:
      secret: ${JWT_SECRET}  # Use environment variable
```

**✅ Solutions:**

**1. Token Expiration Issue:**
```yaml
# Increase token expiration for testing
ricardo:
  auth:
    jwt:
      expiration: 86400000  # 24 hours instead of default
```

**2. JWT Secret Mismatch:**
```bash
# Set consistent environment variable
export JWT_SECRET="your-consistent-secret-key-across-all-environments"
```

**3. Token Malformed:**
```bash
# Get fresh token
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }' | jq -r '.token'
```

### Token Validation Errors

**❌ Error Messages:**
```json
{
  "error": "Unauthorized",
  "message": "JWT token is missing or invalid"
}
```

**✅ Solutions:**

**1. Missing Authorization Header:**
```bash
# ✅ Correct header format
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
     http://localhost:8080/api/auth/me

# ❌ Missing header
curl http://localhost:8080/api/auth/me
```

**2. Malformed Token:**
```bash
# Verify token has 3 parts separated by dots
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiZXhwIjoxNjQwOTk1MjAwfQ.signature" | tr '.' '\n' | wc -l
# Should output: 3
```

**3. Debug Token Validation:**
```java
@RestController
public class TokenDebugController {
    
    @Autowired
    private JwtService jwtService;
    
    @PostMapping("/debug/validate-token")
    public ResponseEntity<Map<String, Object>> validateToken(@RequestBody String token) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            boolean isValid = jwtService.validateToken(token);
            String username = jwtService.extractUsername(token);
            Date expiration = jwtService.extractExpiration(token);
            
            result.put("valid", isValid);
            result.put("username", username);
            result.put("expiration", expiration);
            result.put("expired", expiration.before(new Date()));
            
        } catch (Exception e) {
            result.put("error", e.getMessage());
            result.put("valid", false);
        }
        
        return ResponseEntity.ok(result);
    }
}
```

## User Registration Issues

### User Creation Fails

**❌ Common Errors:**
```json
{
  "error": "Bad Request",
  "message": "User already exists with email: test@example.com"
}
```

**✅ Solutions:**

**1. Check for Existing Users:**
```bash
# Check if email is already registered
curl -X GET "http://localhost:8080/api/users/exists/test@example.com"
```

**2. Use Different Email/Username:**
```bash
curl -X POST http://localhost:8080/api/users/create \
  -H "Content-Type: application/json" \
  -d '{
    "username": "uniqueuser123",
    "email": "unique@example.com",
    "password": "SecurePass123!"
  }'
```

**3. Password Policy Violations:**
```bash
# Check password meets requirements
curl -X POST http://localhost:8080/api/users/create \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com", 
    "password": "StrongPassword123!"
  }'
```

### Database Constraint Violations

**❌ Error:**
```
Duplicate entry 'test@example.com' for key 'users.UK_email'
```

**✅ Solutions:**

**1. Handle Duplicate Gracefully:**
```java
@RestControllerAdvice
public class UserExceptionHandler {
    
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> handleDuplicateUser(DataIntegrityViolationException e) {
        if (e.getMessage().contains("email")) {
            return ResponseEntity.badRequest()
                .body(new ErrorResponse("Email already exists"));
        }
        if (e.getMessage().contains("username")) {
            return ResponseEntity.badRequest()
                .body(new ErrorResponse("Username already exists"));
        }
        return ResponseEntity.internalServerError()
            .body(new ErrorResponse("Database error"));
    }
}
```

**2. Pre-validate Before Creation:**
```java
@Service
public class UserValidationService {
    
    public void validateUserCreation(CreateUserRequestDTO request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("Email already registered");
        }
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UserAlreadyExistsException("Username already taken");
        }
    }
}
```

## Permission and Role Issues

### Access Denied for Protected Endpoints

**❌ Error:**
```json
{
  "error": "Forbidden",
  "message": "Access Denied"
}
```

**✅ Solutions:**

**1. Check User Roles:**
```bash
# Get current user info including roles
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8080/api/auth/me
```

**2. Verify Role Assignment:**
```java
// Assign roles during user creation
User user = new User(username, email, password);
user.addRole(AppRole.USER);  // Ensure role is assigned
user.addRole(AppRole.ADMIN); // For admin access
userService.createUser(user);
```

**3. Check Endpoint Security Configuration:**
```java
@GetMapping("/admin/users")
@PreAuthorize("hasRole('ADMIN')")  // Ensure correct role name
public ResponseEntity<List<UserDTO>> getUsers() {
    // endpoint logic
}
```

### Role-Based Access Not Working

**✅ Debug Role Issues:**

**1. Enable Security Logging:**
```yaml
logging:
  level:
    org.springframework.security.access: DEBUG
    org.springframework.security.web.access: DEBUG
```

**2. Check Role Prefix:**
```java
// Spring Security expects "ROLE_" prefix
// Ricardo Auth handles this automatically, but verify:
@PreAuthorize("hasRole('USER')")        // ✅ Correct
@PreAuthorize("hasRole('ROLE_USER')")   // ❌ Double prefix
```

**3. Custom Role Check:**
```java
@RestController
public class RoleDebugController {
    
    @GetMapping("/debug/roles")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Map<String, Object>> debugRoles(Authentication auth) {
        Map<String, Object> info = new HashMap<>();
        info.put("username", auth.getName());
        info.put("authorities", auth.getAuthorities());
        info.put("authenticated", auth.isAuthenticated());
        return ResponseEntity.ok(info);
    }
}
```

## CORS Issues

### Cross-Origin Request Blocked

**❌ Error:**
```
Access to fetch at 'http://localhost:8080/api/auth/login' from origin 'http://localhost:3000' 
has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource.
```

**✅ Solutions:**

**1. Configure CORS in Application Properties:**
```yaml
spring:
  web:
    cors:
      allowed-origins: 
        - "http://localhost:3000"
        - "https://yourdomain.com"
      allowed-methods: 
        - GET
        - POST
        - PUT
        - DELETE
        - OPTIONS
      allowed-headers: "*"
      allow-credentials: true
```

**2. Custom CORS Configuration:**
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

**3. Controller-Level CORS:**
```java
@RestController
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
@RequestMapping("/api/auth")
public class AuthController {
    // controller methods
}
```

### Preflight Request Issues

**❌ Error:**
```
CORS policy: Response to preflight request doesn't pass access control check
```

**✅ Solution - Handle OPTIONS Requests:**
```java
@RequestMapping(value = "/**", method = RequestMethod.OPTIONS)
public ResponseEntity<?> handleOptions() {
    return ResponseEntity.ok()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        .header("Access-Control-Allow-Headers", "authorization, content-type")
        .build();
}
```

## Session Problems

### Session Not Persisting

**❌ Problem:** User gets logged out immediately

**✅ Solutions:**

**1. Check JWT Expiration:**
```yaml
ricardo:
  auth:
    jwt:
      expiration: 86400000  # 24 hours (not too short)
```

**2. Client-Side Token Storage:**
```javascript
// Store token properly
localStorage.setItem('authToken', response.token);

// Include in requests
const token = localStorage.getItem('authToken');
fetch('/api/protected', {
    headers: {
        'Authorization': `Bearer ${token}`
    }
});
```

**3. Check Cookie Settings (if using cookies):**
```yaml
server:
  servlet:
    session:
      cookie:
        http-only: true
        secure: false  # Set to true in production with HTTPS
        max-age: 86400
```

## Testing and Debugging

### Integration Testing Authentication

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class AuthenticationIntegrationTest {
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Test
    public void testFullAuthenticationFlow() {
        // 1. Create user
        CreateUserRequestDTO createRequest = new CreateUserRequestDTO();
        createRequest.setUsername("testuser");
        createRequest.setEmail("test@example.com");
        createRequest.setPassword("TestPassword123!");
        
        ResponseEntity<UserDTO> createResponse = restTemplate.postForEntity(
            "/api/users/create", createRequest, UserDTO.class);
        
        assertThat(createResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        
        // 2. Login
        LoginRequestDTO loginRequest = new LoginRequestDTO();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("TestPassword123!");
        
        ResponseEntity<TokenDTO> loginResponse = restTemplate.postForEntity(
            "/api/auth/login", loginRequest, TokenDTO.class);
        
        assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        String token = loginResponse.getBody().getToken();
        assertThat(token).isNotNull();
        
        // 3. Access protected endpoint
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        HttpEntity<Void> entity = new HttpEntity<>(headers);
        
        ResponseEntity<AuthenticatedUserDTO> meResponse = restTemplate.exchange(
            "/api/auth/me", HttpMethod.GET, entity, AuthenticatedUserDTO.class);
        
        assertThat(meResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(meResponse.getBody().getUsername()).isEqualTo("test@example.com");
    }
}
```

### Debug Helper Methods

```java
@Component
public class AuthDebugHelper {
    
    public void logTokenDetails(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length == 3) {
                String header = new String(Base64.getDecoder().decode(parts[0]));
                String payload = new String(Base64.getDecoder().decode(parts[1]));
                
                System.out.println("Token Header: " + header);
                System.out.println("Token Payload: " + payload);
            }
        } catch (Exception e) {
            System.out.println("Invalid token format: " + e.getMessage());
        }
    }
    
    public void logUserDetails(Authentication auth) {
        if (auth != null) {
            System.out.println("Username: " + auth.getName());
            System.out.println("Authorities: " + auth.getAuthorities());
            System.out.println("Authenticated: " + auth.isAuthenticated());
        } else {
            System.out.println("No authentication found");
        }
    }
}
```

### Common Debugging Commands

```bash
# 1. Test user creation
curl -v -X POST http://localhost:8080/api/users/create \
  -H "Content-Type: application/json" \
  -d '{"username":"debug","email":"debug@test.com","password":"DebugPass123!"}'

# 2. Test login
curl -v -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"debug@test.com","password":"DebugPass123!"}'

# 3. Test protected endpoint
curl -v -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8080/api/auth/me

# 4. Check application health
curl http://localhost:8080/actuator/health

# 5. Decode JWT token online
# Visit: https://jwt.io and paste your token
```

This comprehensive authentication troubleshooting guide covers the most common issues and their solutions. Use the diagnostic steps to identify problems quickly and apply the appropriate solutions.
