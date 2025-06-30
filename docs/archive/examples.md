# Examples and Use Cases

This guide shows you **exactly how to implement** Ricardo Auth in real applications. Each example includes complete code, configuration, and step-by-step instructions.

> 💡 **Tip:** Start with the Basic Web Application example if you're new to Ricardo Auth.

## 📋 Quick Reference

| Example | Best For | Complexity | Time |
|---------|----------|------------|------|
| [Basic Web Application](#basic-web-application) | Learning, simple apps | ⭐ Easy | 15 min |
| [Mobile API Backend](#mobile-api-backend) | REST APIs, mobile apps | ⭐⭐ Medium | 25 min |
| [Microservices Architecture](#microservices-architecture) | Enterprise, scalable systems | ⭐⭐⭐ Advanced | 45 min |
| [E-commerce Platform](#e-commerce-application) | Business applications | ⭐⭐ Medium | 35 min |

## 🏁 Basic Web Application

**Perfect for:** Learning Ricardo Auth, simple web applications, prototypes

### What You'll Build
A simple Spring Boot web app with user registration, login, and protected pages.

### Project Structure
```
my-web-app/
├── src/main/java/com/mycompany/webapp/
│   ├── WebAppApplication.java
│   └── controller/
│       └── HomeController.java
├── src/main/resources/
│   ├── application.yml
│   └── templates/
│       ├── index.html
│       ├── login.html
│       └── dashboard.html
└── pom.xml
```

### Step 1: Dependencies (pom.xml)
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
    
    <!-- Database (H2 for quick start) -->
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <scope>runtime</scope>
    </dependency>
    
    <!-- Thymeleaf for templates -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId>
    </dependency>
</dependencies>
```

### Step 2: Configuration (application.yml)
```yaml
spring:
  application:
    name: my-web-app
  
  # Database configuration
  datasource:
    url: jdbc:h2:mem:webapp
    driver-class-name: org.h2.Driver
    username: sa
    password: password
  
  jpa:
    hibernate:
      ddl-auto: create-drop
    show-sql: false
  
  h2:
    console:
      enabled: true

# Ricardo Auth configuration
ricardo:
  auth:
    jwt:
      secret: "my-super-secure-development-secret-key-for-webapp-should-be-256-bits"
      expiration: 86400000  # 24 hours for development
    
    # Password policy (optional - these are the defaults)
    password-policy:
      min-length: 8
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      prevent-common-passwords: true
```

### Step 3: Main Application Class
```java
package com.mycompany.webapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class WebAppApplication {
    public static void main(String[] args) {
        SpringApplication.run(WebAppApplication.class, args);
    }
}
```

### Step 4: Simple Web Controller
```java
package com.mycompany.webapp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
    
    @GetMapping("/")
    public String home() {
        return "index";
    }
    
    @GetMapping("/login")
    public String login() {
        return "login";
    }
    
    @GetMapping("/dashboard")
    public String dashboard() {
        return "dashboard";
    }
}
```

### Step 5: Test It Out

1. **Start your application:**
   ```bash
   mvn spring-boot:run
   ```

2. **Create a test user:**
   ```bash
   curl -X POST http://localhost:8080/api/users/create \
     -H "Content-Type: application/json" \
     -d '{
       "username": "testuser",
       "email": "test@example.com",
       "password": "TestPass@123!"
     }'
   ```

3. **Login to get a JWT token:**
   ```bash
   curl -X POST http://localhost:8080/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{
       "email": "test@example.com",
       "password": "TestPass@123!"
     }'
   ```

4. **Use the token:**
   ```bash
   curl -H "Authorization: Bearer YOUR_TOKEN" \
        http://localhost:8080/api/auth/me
   ```

✅ **You now have a working Spring Boot app with JWT authentication!**
    controllers:
      auth:
        enabled: true
      user:
        enabled: true

server:
  port: 8080

logging:
  level:
    com.ricardo.auth: INFO
```

### Main Application
```java
package com.mycompany.webapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class WebAppApplication {
    public static void main(String[] args) {
        SpringApplication.run(WebAppApplication.class, args);
    }
}
```

### Protected Controller
```java
package com.mycompany.webapp.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
    
    @GetMapping("/")
    public String home() {
        return "index";
    }
    
    @GetMapping("/login")
    public String login() {
        return "login";
    }
    
    @GetMapping("/dashboard")
    @PreAuthorize("hasRole('USER')")
    public String dashboard(Authentication authentication, Model model) {
        model.addAttribute("username", authentication.getName());
        return "dashboard";
    }
    
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String admin(Authentication authentication, Model model) {
        model.addAttribute("username", authentication.getName());
        return "admin";
    }
}
```

### Frontend Integration (JavaScript)
```javascript
// auth.js - Authentication utilities
class AuthService {
    constructor() {
        this.token = sessionStorage.getItem('authToken');
        this.baseUrl = window.location.origin;
    }

    async login(email, password) {
        try {
            const response = await fetch(`${this.baseUrl}/api/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });

            if (response.ok) {
                const data = await response.json();
                this.token = data.token;
                sessionStorage.setItem('authToken', this.token);
                return { success: true, token: this.token };
            } else {
                const error = await response.json();
                return { success: false, error: error.message };
            }
        } catch (error) {
            return { success: false, error: 'Network error' };
        }
    }

    async getCurrentUser() {
        if (!this.token) return null;

        try {
            const response = await fetch(`${this.baseUrl}/api/auth/me`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            if (response.ok) {
                return await response.json();
            }
        } catch (error) {
            console.error('Failed to get current user:', error);
        }
        return null;
    }

    logout() {
        this.token = null;
        sessionStorage.removeItem('authToken');
        window.location.href = '/login';
    }

    isAuthenticated() {
        return !!this.token;
    }

    getAuthHeaders() {
        return {
            'Authorization': `Bearer ${this.token}`,
            'Content-Type': 'application/json'
        };
    }
}

// Usage in your web pages
const authService = new AuthService();

// Login form handler
document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            
            const result = await authService.login(email, password);
            
            if (result.success) {
                window.location.href = '/dashboard';
            } else {
                document.getElementById('error').textContent = result.error;
            }
        });
    }
});
```

## Microservices Architecture

### API Gateway Configuration
```yaml
# application-gateway.yml
spring:
  application:
    name: api-gateway
  cloud:
    gateway:
      routes:
        - id: auth-service
          uri: http://localhost:8081
          predicates:
            - Path=/auth/**
          filters:
            - StripPrefix=1
        
        - id: user-service
          uri: http://localhost:8082
          predicates:
            - Path=/users/**
          filters:
            - StripPrefix=1
            - name: AuthFilter

ricardo:
  auth:
    jwt:
      secret: ${JWT_SECRET}
    controllers:
      auth:
        enabled: true
      user:
        enabled: false  # Handled by dedicated user service
```

### User Service
```java
// UserServiceApplication.java
@SpringBootApplication
@EnableJpaRepositories
public class UserServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(UserServiceApplication.class, args);
    }
}

// Enhanced User Controller
@RestController
@RequestMapping("/api/users")
public class EnhancedUserController {
    
    private final UserService userService;
    private final JwtService jwtService;
    
    @PostMapping("/profile")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<UserProfileDTO> updateProfile(
            @RequestBody UpdateProfileRequestDTO request,
            Authentication authentication) {
        
        String email = authentication.getName();
        User user = userService.getUserByEmail(email);
        
        // Update profile fields
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPhoneNumber(request.getPhoneNumber());
        
        User updatedUser = userService.updateUser(user.getId(), user);
        return ResponseEntity.ok(UserProfileMapper.toDTO(updatedUser));
    }
    
    @GetMapping("/search")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<UserDTO>> searchUsers(
            @RequestParam(required = false) String query,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        
        Pageable pageable = PageRequest.of(page, size);
        Page<User> users = userService.searchUsers(query, pageable);
        Page<UserDTO> userDTOs = users.map(UserDTOMapper::toDTO);
        
        return ResponseEntity.ok(userDTOs);
    }
}
```

### Service Configuration
```yaml
# user-service application.yml
spring:
  application:
    name: user-service
  datasource:
    url: jdbc:postgresql://localhost:5432/userdb
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}

ricardo:
  auth:
    jwt:
      secret: ${JWT_SECRET}  # Same secret across all services
    controllers:
      auth:
        enabled: false  # Auth handled by gateway
      user:
        enabled: true

eureka:
  client:
    service-url:
      defaultZone: http://localhost:8761/eureka/
```

## Mobile API Backend

### Mobile-Optimized Configuration
```yaml
# application-mobile.yml
ricardo:
  auth:
    jwt:
      secret: ${JWT_SECRET}
      expiration: 604800000  # 7 days for mobile apps
    controllers:
      auth:
        enabled: true
      user:
        enabled: true

spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/mobileapp
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
    hikari:
      maximum-pool-size: 20
      connection-timeout: 30000

# Mobile-specific configurations
server:
  compression:
    enabled: true
  http2:
    enabled: true

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
```

### Mobile API Controller
```java
@RestController
@RequestMapping("/api/mobile")
@CrossOrigin(origins = "*", allowedHeaders = "*")  // Configure properly for production
public class MobileApiController {
    
    private final UserService userService;
    private final JwtService jwtService;
    
    @PostMapping("/auth/login")
    public ResponseEntity<MobileLoginResponseDTO> mobileLogin(
            @RequestBody MobileLoginRequestDTO request) {
        
        // Enhanced login with device information
        String deviceId = request.getDeviceId();
        String deviceType = request.getDeviceType(); // iOS, Android
        
        // Authenticate user
        Authentication auth = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        
        UserDetails userDetails = (UserDetails) auth.getPrincipal();
        String token = jwtService.generateToken(userDetails.getUsername(), userDetails.getAuthorities());
        
        // Store device information (optional)
        userService.updateDeviceInfo(userDetails.getUsername(), deviceId, deviceType);
        
        MobileLoginResponseDTO response = new MobileLoginResponseDTO();
        response.setToken(token);
        response.setExpiresIn(604800000L); // 7 days
        response.setTokenType("Bearer");
        response.setUser(UserDTOMapper.toMobileDTO(userService.getUserByEmail(userDetails.getUsername())));
        
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/auth/refresh")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<TokenDTO> refreshToken(Authentication authentication) {
        String newToken = jwtService.generateToken(
            authentication.getName(), 
            authentication.getAuthorities()
        );
        return ResponseEntity.ok(new TokenDTO(newToken));
    }
    
    @GetMapping("/profile")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<MobileUserDTO> getProfile(Authentication authentication) {
        User user = userService.getUserByEmail(authentication.getName());
        return ResponseEntity.ok(UserDTOMapper.toMobileDTO(user));
    }
    
    @PutMapping("/profile")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<MobileUserDTO> updateProfile(
            @RequestBody @Valid UpdateMobileProfileDTO request,
            Authentication authentication) {
        
        User user = userService.getUserByEmail(authentication.getName());
        
        // Update mobile-specific fields
        user.setDisplayName(request.getDisplayName());
        user.setAvatarUrl(request.getAvatarUrl());
        user.setNotificationPreferences(request.getNotificationPreferences());
        
        User updatedUser = userService.updateUser(user.getId(), user);
        return ResponseEntity.ok(UserDTOMapper.toMobileDTO(updatedUser));
    }
}
```

### Mobile DTOs
```java
// Mobile-optimized DTOs
public class MobileLoginRequestDTO {
    @NotBlank
    private String email;
    
    @NotBlank
    private String password;
    
    private String deviceId;
    private String deviceType;
    private String appVersion;
    
    // getters and setters
}

public class MobileLoginResponseDTO {
    private String token;
    private String tokenType;
    private Long expiresIn;
    private MobileUserDTO user;
    
    // getters and setters
}

public class MobileUserDTO {
    private Long id;
    private String username;
    private String email;
    private String displayName;
    private String avatarUrl;
    private Map<String, Boolean> notificationPreferences;
    private LocalDateTime lastLoginAt;
    
    // getters and setters
}
```

## Multi-Tenant Application

### Tenant-Aware Configuration
```java
@Configuration
@EnableJpaRepositories
public class MultiTenantConfig {
    
    @Bean
    @Primary
    public DataSource dataSource() {
        return new TenantAwareDataSource();
    }
    
    @Bean
    public TenantResolver tenantResolver() {
        return new HeaderTenantResolver();
    }
}

// Tenant resolution from HTTP headers
public class HeaderTenantResolver implements TenantResolver {
    
    @Override
    public String resolveTenant(HttpServletRequest request) {
        String tenant = request.getHeader("X-Tenant-ID");
        if (tenant == null || tenant.isEmpty()) {
            throw new IllegalArgumentException("Tenant ID is required");
        }
        return tenant;
    }
}

// Tenant-aware User Service
@Service
@Transactional
public class TenantAwareUserService extends UserServiceImpl {
    
    @Override
    public User createUser(User user) {
        String tenantId = TenantContext.getCurrentTenant();
        user.setTenantId(tenantId);
        return super.createUser(user);
    }
    
    @Override
    public User getUserByEmail(String email) {
        String tenantId = TenantContext.getCurrentTenant();
        return userRepository.findByEmailAndTenantId(email, tenantId)
            .orElseThrow(() -> new UserNotFoundException("User not found: " + email));
    }
}
```

### Multi-Tenant User Entity
```java
@Entity
@Table(name = "users")
public class TenantAwareUser extends User {
    
    @Column(name = "tenant_id", nullable = false)
    private String tenantId;
    
    // Additional tenant-specific fields
    @Column(name = "tenant_role")
    private String tenantRole;
    
    @Column(name = "tenant_permissions")
    @Convert(converter = JsonConverter.class)
    private Set<String> tenantPermissions;
    
    // getters and setters
}
```

## Social Media Platform

### Enhanced User Features
```java
@Entity
public class SocialUser extends User {
    
    @Column(name = "display_name")
    private String displayName;
    
    @Column(name = "bio", length = 500)
    private String bio;
    
    @Column(name = "avatar_url")
    private String avatarUrl;
    
    @Column(name = "follower_count")
    private Integer followerCount = 0;
    
    @Column(name = "following_count")
    private Integer followingCount = 0;
    
    @Column(name = "post_count")
    private Integer postCount = 0;
    
    @Column(name = "is_verified")
    private Boolean isVerified = false;
    
    @Column(name = "is_private")
    private Boolean isPrivate = false;
    
    // getters and setters
}

@RestController
@RequestMapping("/api/social")
public class SocialController {
    
    private final SocialUserService socialUserService;
    private final FollowService followService;
    
    @PostMapping("/follow/{userId}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Void> followUser(
            @PathVariable Long userId,
            Authentication authentication) {
        
        String currentUserEmail = authentication.getName();
        User currentUser = socialUserService.getUserByEmail(currentUserEmail);
        
        followService.followUser(currentUser.getId(), userId);
        return ResponseEntity.ok().build();
    }
    
    @DeleteMapping("/follow/{userId}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Void> unfollowUser(
            @PathVariable Long userId,
            Authentication authentication) {
        
        String currentUserEmail = authentication.getName();
        User currentUser = socialUserService.getUserByEmail(currentUserEmail);
        
        followService.unfollowUser(currentUser.getId(), userId);
        return ResponseEntity.ok().build();
    }
    
    @GetMapping("/feed")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Page<PostDTO>> getFeed(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            Authentication authentication) {
        
        String userEmail = authentication.getName();
        User user = socialUserService.getUserByEmail(userEmail);
        
        Pageable pageable = PageRequest.of(page, size);
        Page<Post> posts = postService.getFeedForUser(user.getId(), pageable);
        
        return ResponseEntity.ok(posts.map(PostDTOMapper::toDTO));
    }
}
```

## E-commerce Application

### Enhanced Authentication for E-commerce
```java
@RestController
@RequestMapping("/api/shop")
public class ShopAuthController {
    
    private final UserService userService;
    private final CustomerService customerService;
    private final CartService cartService;
    
    @PostMapping("/register")
    public ResponseEntity<CustomerRegistrationResponseDTO> registerCustomer(
            @RequestBody @Valid CustomerRegistrationRequestDTO request) {
        
        // Create user account
        User user = new User(
            Username.valueOf(request.getUsername()),
            Email.valueOf(request.getEmail()),
            Password.valueOf(request.getPassword(), passwordEncoder)
        );
        user.addRole(AppRole.USER);
        User createdUser = userService.createUser(user);
        
        // Create customer profile
        Customer customer = new Customer();
        customer.setUser(createdUser);
        customer.setFirstName(request.getFirstName());
        customer.setLastName(request.getLastName());
        customer.setPhoneNumber(request.getPhoneNumber());
        Customer createdCustomer = customerService.createCustomer(customer);
        
        // Initialize shopping cart
        Cart cart = cartService.createCartForCustomer(createdCustomer.getId());
        
        CustomerRegistrationResponseDTO response = new CustomerRegistrationResponseDTO();
        response.setCustomerId(createdCustomer.getId());
        response.setUser(UserDTOMapper.toDTO(createdUser));
        response.setCartId(cart.getId());
        
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
    
    @PostMapping("/login")
    public ResponseEntity<ShopLoginResponseDTO> shopLogin(
            @RequestBody LoginRequestDTO request) {
        
        // Authenticate user
        Authentication auth = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        
        UserDetails userDetails = (UserDetails) auth.getPrincipal();
        String token = jwtService.generateToken(userDetails.getUsername(), userDetails.getAuthorities());
        
        // Get customer information
        User user = userService.getUserByEmail(userDetails.getUsername());
        Customer customer = customerService.getCustomerByUserId(user.getId());
        Cart cart = cartService.getCartByCustomerId(customer.getId());
        
        ShopLoginResponseDTO response = new ShopLoginResponseDTO();
        response.setToken(token);
        response.setCustomer(CustomerDTOMapper.toDTO(customer));
        response.setCartItemCount(cart.getItems().size());
        response.setWishlistItemCount(wishlistService.getWishlistItemCount(customer.getId()));
        
        return ResponseEntity.ok(response);
    }
}

// Customer-specific DTOs
public class CustomerRegistrationRequestDTO {
    @NotBlank
    private String username;
    
    @NotBlank
    @Email
    private String email;
    
    @NotBlank
    @Size(min = 8)
    private String password;
    
    @NotBlank
    private String firstName;
    
    @NotBlank
    private String lastName;
    
    @Pattern(regexp = "^\\+?[1-9]\\d{1,14}$")
    private String phoneNumber;
    
    // getters and setters
}
```

## Custom Integrations

### OAuth2 Integration
```java
@Configuration
@EnableWebSecurity
public class OAuth2SecurityConfig {
    
    @Bean
    public SecurityFilterChain oauth2FilterChain(HttpSecurity http) throws Exception {
        return http
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/oauth2/authorization/google")
                .defaultSuccessUrl("/oauth2/success")
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(customOAuth2UserService())
                )
            )
            .build();
    }
    
    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> customOAuth2UserService() {
        return new CustomOAuth2UserService();
    }
}

@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    
    private final UserService userService;
    private final JwtService jwtService;
    
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = new DefaultOAuth2UserService().loadUser(userRequest);
        
        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");
        
        // Create or update user
        User user;
        try {
            user = userService.getUserByEmail(email);
        } catch (UserNotFoundException e) {
            // Create new user from OAuth2 data
            user = new User(
                Username.valueOf(email),
                Email.valueOf(email),
                Password.valueOf("oauth2", passwordEncoder) // Placeholder password
            );
            user.addRole(AppRole.USER);
            user = userService.createUser(user);
        }
        
        return new CustomOAuth2User(oauth2User, user);
    }
}
```

### External API Integration
```java
@RestController
@RequestMapping("/api/external")
public class ExternalIntegrationController {
    
    private final ExternalApiService externalApiService;
    private final UserService userService;
    
    @PostMapping("/sync-profile")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<SyncResponseDTO> syncExternalProfile(
            @RequestBody ExternalSyncRequestDTO request,
            Authentication authentication) {
        
        String userEmail = authentication.getName();
        User user = userService.getUserByEmail(userEmail);
        
        // Validate external API token
        if (!externalApiService.validateToken(request.getExternalToken())) {
            throw new InvalidTokenException("Invalid external API token");
        }
        
        // Fetch data from external API
        ExternalProfileData externalData = externalApiService.getProfile(request.getExternalToken());
        
        // Update user profile with external data
        user.setDisplayName(externalData.getDisplayName());
        user.setAvatarUrl(externalData.getAvatarUrl());
        
        User updatedUser = userService.updateUser(user.getId(), user);
        
        SyncResponseDTO response = new SyncResponseDTO();
        response.setSyncedAt(LocalDateTime.now());
        response.setUser(UserDTOMapper.toDTO(updatedUser));
        
        return ResponseEntity.ok(response);
    }
}
```

### Webhook Integration
```java
@RestController
@RequestMapping("/api/webhooks")
public class WebhookController {
    
    private final UserService userService;
    private final NotificationService notificationService;
    
    @PostMapping("/user-events")
    public ResponseEntity<Void> handleUserEvent(
            @RequestBody WebhookEventDTO event,
            @RequestHeader("X-Webhook-Signature") String signature) {
        
        // Verify webhook signature
        if (!webhookService.verifySignature(event, signature)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        
        switch (event.getType()) {
            case "user.created":
                handleUserCreated(event);
                break;
            case "user.updated":
                handleUserUpdated(event);
                break;
            case "user.deleted":
                handleUserDeleted(event);
                break;
            default:
                log.warn("Unknown webhook event type: {}", event.getType());
        }
        
        return ResponseEntity.ok().build();
    }
    
    private void handleUserCreated(WebhookEventDTO event) {
        // Send welcome email
        String userEmail = event.getData().get("email").toString();
        notificationService.sendWelcomeEmail(userEmail);
    }
}
```

## Testing Examples

### Integration Test Example
```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional
public class AuthIntegrationTest {
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Autowired
    private UserService userService;
    
    @Test
    public void testFullAuthFlow() {
        // Create user
        CreateUserRequestDTO createRequest = new CreateUserRequestDTO();
        createRequest.setUsername("testuser");
        createRequest.setEmail("test@example.com");
        createRequest.setPassword("password123");
        
        ResponseEntity<UserDTO> createResponse = restTemplate.postForEntity(
            "/api/users/create", createRequest, UserDTO.class);
        
        assertThat(createResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        
        // Login
        LoginRequestDTO loginRequest = new LoginRequestDTO();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("password123");
        
        ResponseEntity<TokenDTO> loginResponse = restTemplate.postForEntity(
            "/api/auth/login", loginRequest, TokenDTO.class);
        
        assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        String token = loginResponse.getBody().getToken();
        
        // Access protected endpoint
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

These examples demonstrate how to integrate and customize the Ricardo Auth Spring Boot Starter for various application types and use cases. Each example can be adapted and extended based on your specific requirements.
