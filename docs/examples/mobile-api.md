# Mobile API Backend

**Perfect for:** REST APIs, mobile applications, single-page applications  
**Complexity:** ⭐⭐ Medium  
**Time:** 25 minutes  

## What You'll Build

A robust REST API backend for mobile applications with:
- ✅ Mobile-optimized JWT authentication
- ✅ User management endpoints
- ✅ Extended token expiration for mobile use
- ✅ CORS configuration for cross-origin requests
- ✅ Rate limiting and security headers
- ✅ API documentation and testing examples

## Project Structure

```
mobile-api-backend/
├── src/main/java/com/mycompany/mobileapi/
│   ├── MobileApiApplication.java
│   ├── controller/
│   │   ├── MobileAuthController.java
│   │   └── MobileUserController.java
│   ├── config/
│   │   ├── CorsConfig.java
│   │   └── SecurityConfig.java
│   ├── dto/
│   │   ├── MobileLoginResponse.java
│   │   └── UserProfileDTO.java
│   └── service/
│       └── MobileUserService.java
├── src/main/resources/
│   └── application.yml
└── pom.xml
```

## Step 1: Dependencies (pom.xml)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.3.0</version>
        <relativePath/>
    </parent>
    
    <groupId>com.mycompany</groupId>
    <artifactId>mobile-api-backend</artifactId>
    <version>1.0.0</version>
    <name>mobile-api-backend</name>
    
    <properties>
        <java.version>17</java.version>
    </properties>
    
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
        
        <!-- Database (PostgreSQL for production) -->
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <scope>runtime</scope>
        </dependency>
        
        <!-- H2 for development -->
        <dependency>
            <groupId>com.h2database</groupId>
            <artifactId>h2</artifactId>
            <scope>runtime</scope>
        </dependency>
        
        <!-- Validation -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
        
        <!-- Actuator for health checks -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>
        
        <!-- Test dependencies -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
    
    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

## Step 2: Mobile-Optimized Configuration

### application.yml
```yaml
spring:
  application:
    name: mobile-api-backend
  
  # Development profile (H2 database)
  profiles:
    active: dev
  
  # Database configuration (overridden by profiles)
  datasource:
    url: jdbc:h2:mem:mobileapi
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

# Mobile-optimized Ricardo Auth configuration
ricardo:
  auth:
    jwt:
      secret: ${JWT_SECRET:mobile-api-development-secret-key-256-bits-long-for-security}
      expiration: 604800000  # 7 days for mobile apps (longer than web)
    
    # Relaxed password policy for mobile demo
    password-policy:
      min-length: 8
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: false  # More lenient for mobile keyboards
      prevent-common-passwords: true
    
    controllers:
      auth:
        enabled: true
      user:
        enabled: true

# Server configuration
server:
  port: 8080
  compression:
    enabled: true
    mime-types: application/json,text/plain

# CORS configuration (development)
cors:
  allowed-origins: 
    - http://localhost:3000
    - http://localhost:8080
    - capacitor://localhost
    - ionic://localhost
  allowed-methods: GET,POST,PUT,DELETE,OPTIONS
  allowed-headers: "*"
  allow-credentials: true

# Actuator endpoints for health checks
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
  endpoint:
    health:
      show-details: always

# Logging
logging:
  level:
    com.ricardo.auth: INFO
    com.mycompany.mobileapi: DEBUG
    org.springframework.security: WARN

---
# Production profile
spring:
  config:
    activate:
      on-profile: prod
  
  # Production database (PostgreSQL)
  datasource:
    url: ${DATABASE_URL}
    username: ${DATABASE_USERNAME}
    password: ${DATABASE_PASSWORD}
    hikari:
      maximum-pool-size: 20
      connection-timeout: 30000
      idle-timeout: 600000
  
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false

# Production security settings
ricardo:
  auth:
    jwt:
      secret: ${JWT_SECRET}
      expiration: 2592000000  # 30 days for production mobile apps
    
    password-policy:
      min-length: 10
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      prevent-common-passwords: true

# Production CORS (more restrictive)
cors:
  allowed-origins: 
    - https://yourmobileapp.com
    - https://yourwebapp.com
  allowed-methods: GET,POST,PUT,DELETE
  allowed-headers: Authorization,Content-Type,Accept
  allow-credentials: true
```

## Step 3: Main Application Class

```java
package com.mycompany.mobileapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Mobile API Backend Application
 * 
 * Provides JWT authentication and user management specifically
 * optimized for mobile applications.
 */
@SpringBootApplication
public class MobileApiApplication {
    public static void main(String[] args) {
        SpringApplication.run(MobileApiApplication.class, args);
    }
}
```

## Step 4: CORS Configuration

```java
package com.mycompany.mobileapi.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * CORS configuration for mobile applications
 */
@Configuration
public class CorsConfig {
    
    @Value("${cors.allowed-origins}")
    private List<String> allowedOrigins;
    
    @Value("${cors.allowed-methods}")
    private String allowedMethods;
    
    @Value("${cors.allowed-headers}")
    private String allowedHeaders;
    
    @Value("${cors.allow-credentials}")
    private boolean allowCredentials;
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Set allowed origins (mobile apps, web apps, etc.)
        configuration.setAllowedOrigins(allowedOrigins);
        
        // Set allowed methods
        configuration.setAllowedMethods(Arrays.asList(allowedMethods.split(",")));
        
        // Set allowed headers
        if ("*".equals(allowedHeaders)) {
            configuration.addAllowedHeader("*");
        } else {
            configuration.setAllowedHeaders(Arrays.asList(allowedHeaders.split(",")));
        }
        
        // Allow credentials (for cookies, authorization headers)
        configuration.setAllowCredentials(allowCredentials);
        
        // Apply configuration to all paths
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        
        return source;
    }
}
```

## Step 5: Mobile-Specific Controllers

### Enhanced Mobile Auth Controller

```java
package com.mycompany.mobileapi.controller;

import com.mycompany.mobileapi.dto.MobileLoginResponse;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.domain.user.User;
import com.ricardo.auth.dto.LoginRequestDTO;
import com.ricardo.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;

/**
 * Mobile-optimized authentication controller
 */
@RestController
@RequestMapping("/api/mobile/auth")
@CrossOrigin(origins = {"*"})
public class MobileAuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserService userService;

    /**
     * Mobile login endpoint with extended response
     */
    @PostMapping("/login")
    public ResponseEntity<?> mobileLogin(@Valid @RequestBody LoginRequestDTO loginRequest) {
        try {
            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail(),
                            loginRequest.getPassword()
                    )
            );

            // Generate JWT token
            String token = jwtService.generateAccessToken(
                    authentication.getName(),
                    authentication.getAuthorities()
            );

            // Get user details
            User user = userService.getUserByEmail(loginRequest.getEmail());

            // Return mobile-optimized response
            MobileLoginResponse response = new MobileLoginResponse(
                    token,
                    user.getId(),
                    user.getUsername().getValue(),
                    user.getEmail().getValue(),
                    user.getRoles(),
                    System.currentTimeMillis() + 604800000L // Token expiry time
            );

            return ResponseEntity.ok(response);

        } catch (AuthenticationException e) {
            return ResponseEntity.status(401)
                    .body(new ErrorResponse("Authentication failed", "Invalid email or password"));
        }
    }

    /**
     * Token validation endpoint for mobile apps
     */
    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String authHeader) {
        try {
            String token = authHeader.replace("Bearer ", "");

            if (jwtService.isTokenValid(token)) {
                String username = jwtService.extractUsername(token);
                User user = userService.getUserByEmail(username);

                return ResponseEntity.ok(new TokenValidationResponse(
                        true,
                        user.getId(),
                        user.getUsername().getValue(),
                        user.getEmail().getValue(),
                        user.getRoles()
                ));
            } else {
                return ResponseEntity.status(401)
                        .body(new TokenValidationResponse(false, null, null, null, null));
            }
        } catch (Exception e) {
            return ResponseEntity.status(401)
                    .body(new TokenValidationResponse(false, null, null, null, null));
        }
    }

    /**
     * Token refresh endpoint
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestHeader("Authorization") String authHeader) {
        try {
            String token = authHeader.replace("Bearer ", "");
            String username = jwtService.extractUsername(token);

            if (jwtService.isTokenValid(token)) {
                com.ricardo.auth.domain.user.User user = userService.getUserByEmail(username);
                String newToken = jwtService.generateAccessToken(username, user.getAuthorities());

                return ResponseEntity.ok(new TokenRefreshResponse(
                        newToken,
                        System.currentTimeMillis() + 604800000L
                ));
            } else {
                return ResponseEntity.status(401)
                        .body(new ErrorResponse("Token refresh failed", "Invalid or expired token"));
            }
        } catch (Exception e) {
            return ResponseEntity.status(401)
                    .body(new ErrorResponse("Token refresh failed", "Invalid token"));
        }
    }
}
```

### Mobile User Controller

```java
package com.mycompany.mobileapi.controller;

import com.mycompany.mobileapi.dto.UserProfileDTO;
import com.mycompany.mobileapi.service.MobileUserService;
import com.ricardo.auth.domain.user.User;
import com.ricardo.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;

/**
 * Mobile-optimized user management controller
 */
@RestController
@RequestMapping("/api/mobile/users")
@CrossOrigin(origins = {"*"})
public class MobileUserController {

    @Autowired
    private UserService userService;

    @Autowired
    private MobileUserService mobileUserService;

    /**
     * Get current user profile
     */
    @GetMapping("/profile")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<UserProfileDTO> getCurrentUserProfile(Authentication authentication) {
        String email = authentication.getName();
        User user = userService.getUserByEmail(email);
        UserProfileDTO profile = mobileUserService.buildUserProfile(user);
        return ResponseEntity.ok(profile);
    }

    /**
     * Update user profile
     */
    @PutMapping("/profile")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<UserProfileDTO> updateProfile(
            @Valid @RequestBody UpdateProfileRequest request,
            Authentication authentication) {

        String email = authentication.getName();
        User user = userService.getUserByEmail(email);

        // Update profile fields
        User updatedUser = mobileUserService.updateUserProfile(user, request);
        UserProfileDTO profile = mobileUserService.buildUserProfile(updatedUser);

        return ResponseEntity.ok(profile);
    }

    /**
     * Change password
     */
    @PostMapping("/change-password")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            Authentication authentication) {

        try {
            String email = authentication.getName();
            mobileUserService.changePassword(email, request);
            return ResponseEntity.ok(new MessageResponse("Password changed successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse("Password change failed", e.getMessage()));
        }
    }

    /**
     * Delete account
     */
    @DeleteMapping("/profile")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> deleteAccount(Authentication authentication) {
        String email = authentication.getName();
        User user = userService.getUserByEmail(email);
        userService.deleteUser(user.getId());
        return ResponseEntity.ok(new MessageResponse("Account deleted successfully"));
    }

    /**
     * Search users (mobile-friendly pagination)
     */
    @GetMapping("/search")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Page<UserProfileDTO>> searchUsers(
            @RequestParam(required = false) String query,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Pageable pageable = PageRequest.of(page, Math.min(size, 50)); // Limit page size for mobile
        Page<User> users = mobileUserService.searchUsers(query, pageable);
        Page<UserProfileDTO> profiles = users.map(mobileUserService::buildUserProfile);

        return ResponseEntity.ok(profiles);
    }
}
```

## Step 6: Mobile-Specific DTOs

### Mobile Login Response

```java
package com.mycompany.mobileapi.dto;

import com.ricardo.auth.core.Role;

import java.util.Set;

/**
 * Enhanced login response for mobile applications
 */
public class MobileLoginResponse {
    private String token;
    private Long userId;
    private String username;
    private String email;
    private Set<Role> roles;
    private Long expiresAt;
    private String tokenType = "Bearer";
    
    public MobileLoginResponse(String token, Long userId, String username, 
                              String email, Set<Role> roles, Long expiresAt) {
        this.token = token;
        this.userId = userId;
        this.username = username;
        this.email = email;
        this.roles = roles;
        this.expiresAt = expiresAt;
    }
    
    // Getters and setters
    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
    
    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public Set<Role> getRoles() { return roles; }
    public void setRoles(Set<Role> roles) { this.roles = roles; }
    
    public Long getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Long expiresAt) { this.expiresAt = expiresAt; }
    
    public String getTokenType() { return tokenType; }
    public void setTokenType(String tokenType) { this.tokenType = tokenType; }
}
```

### User Profile DTO

```java
package com.mycompany.mobileapi.dto;

import com.ricardo.auth.core.Role;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * Mobile-optimized user profile DTO
 */
public class UserProfileDTO {
    private Long id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private String phoneNumber;
    private String profilePictureUrl;
    private Set<Role> roles;
    private LocalDateTime createdAt;
    private LocalDateTime lastLoginAt;
    private boolean isActive;
    
    // Constructors, getters, and setters
    public UserProfileDTO() {}
    
    public UserProfileDTO(Long id, String username, String email) {
        this.id = id;
        this.username = username;
        this.email = email;
    }
    
    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public String getFirstName() { return firstName; }
    public void setFirstName(String firstName) { this.firstName = firstName; }
    
    public String getLastName() { return lastName; }
    public void setLastName(String lastName) { this.lastName = lastName; }
    
    public String getPhoneNumber() { return phoneNumber; }
    public void setPhoneNumber(String phoneNumber) { this.phoneNumber = phoneNumber; }
    
    public String getProfilePictureUrl() { return profilePictureUrl; }
    public void setProfilePictureUrl(String profilePictureUrl) { this.profilePictureUrl = profilePictureUrl; }
    
    public Set<Role> getRoles() { return roles; }
    public void setRoles(Set<Role> roles) { this.roles = roles; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public LocalDateTime getLastLoginAt() { return lastLoginAt; }
    public void setLastLoginAt(LocalDateTime lastLoginAt) { this.lastLoginAt = lastLoginAt; }
    
    public boolean isActive() { return isActive; }
    public void setActive(boolean active) { isActive = active; }
}
```

## Step 7: Mobile User Service

```java
package com.mycompany.mobileapi.service;

import com.mycompany.mobileapi.dto.UserProfileDTO;
import com.ricardo.auth.domain.user.User;
import com.ricardo.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

/**
 * Mobile-specific user service with profile management
 */
@Service
public class MobileUserService {

    @Autowired
    private UserService userService;

    /**
     * Build user profile DTO from user entity
     */
    public UserProfileDTO buildUserProfile(User user) {
        UserProfileDTO profile = new UserProfileDTO();
        profile.setId(user.getId());
        profile.setUsername(user.getUsername().getValue());
        profile.setEmail(user.getEmail().getValue());
        profile.setRoles(user.getRoles());
        profile.setActive(true); // Assuming active users
        // Add other profile fields as needed
        return profile;
    }

    /**
     * Update user profile
     */
    public User updateUserProfile(com.ricardo.auth.domain.user.User user, UpdateProfileRequest request) {
        // Update profile fields
        // Note: In a real implementation, you'd extend the User entity
        // to include firstName, lastName, phoneNumber, etc.

        return userService.updateUser(user.getId(), user);
    }

    /**
     * Change user password
     */
    public void changePassword(String email, ChangePasswordRequest request) {
        User user = userService.getUserByEmail(email);

        // Verify current password
        if (!userService.verifyPassword(user, request.getCurrentPassword())) {
            throw new IllegalArgumentException("Current password is incorrect");
        }

        // Update password
        userService.updatePassword(user.getId(), request.getNewPassword());
    }

    /**
     * Search users with mobile-friendly pagination
     */
    public Page<User> searchUsers(String query, Pageable pageable) {
        // Implement search logic
        // This is a simplified version - in practice, you'd implement
        // full-text search or use a search engine like Elasticsearch

        if (query == null || query.trim().isEmpty()) {
            return userService.getAllUsers(pageable);
        }

        // Search by username or email containing the query
        return userService.searchUsersByQuery(query, pageable);
    }
}
```

## Step 8: Testing the Mobile API

### Test Scripts

#### 1. User Registration
```bash
curl -X POST http://localhost:8080/api/users/create \
  -H "Content-Type: application/json" \
  -d '{
    "username": "mobileuser",
    "email": "mobile@example.com",
    "password": "MobilePass123!"
  }'
```

#### 2. Mobile Login
```bash
curl -X POST http://localhost:8080/api/mobile/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "mobile@example.com",
    "password": "MobilePass123!"
  }'
```

#### 3. Get User Profile
```bash
curl -X GET http://localhost:8080/api/mobile/users/profile \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

#### 4. Validate Token
```bash
curl -X POST http://localhost:8080/api/mobile/auth/validate \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### Mobile App Integration Examples

#### React Native Example
```javascript
// MobileAuthService.js
class MobileAuthService {
    constructor() {
        this.baseUrl = 'http://your-api-server.com';
        this.token = null;
    }

    async login(email, password) {
        try {
            const response = await fetch(`${this.baseUrl}/api/mobile/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password }),
            });

            if (response.ok) {
                const data = await response.json();
                this.token = data.token;
                
                // Store token securely
                await AsyncStorage.setItem('authToken', this.token);
                await AsyncStorage.setItem('userId', data.userId.toString());
                
                return { success: true, user: data };
            } else {
                const error = await response.json();
                return { success: false, error: error.message };
            }
        } catch (error) {
            return { success: false, error: 'Network error' };
        }
    }

    async getProfile() {
        if (!this.token) {
            this.token = await AsyncStorage.getItem('authToken');
        }

        try {
            const response = await fetch(`${this.baseUrl}/api/mobile/users/profile`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`,
                },
            });

            if (response.ok) {
                return await response.json();
            }
        } catch (error) {
            console.error('Failed to get profile:', error);
        }
        return null;
    }

    async validateToken() {
        if (!this.token) return false;

        try {
            const response = await fetch(`${this.baseUrl}/api/mobile/auth/validate`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.token}`,
                },
            });

            return response.ok;
        } catch (error) {
            return false;
        }
    }
}

export default new MobileAuthService();
```

#### Flutter Example
```dart
// mobile_auth_service.dart
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

class MobileAuthService {
  static const String baseUrl = 'http://your-api-server.com';
  String? _token;

  Future<Map<String, dynamic>> login(String email, String password) async {
    try {
      final response = await http.post(
        Uri.parse('$baseUrl/api/mobile/auth/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'email': email, 'password': password}),
      );

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        _token = data['token'];
        
        // Store token securely
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString('authToken', _token!);
        await prefs.setInt('userId', data['userId']);
        
        return {'success': true, 'user': data};
      } else {
        final error = jsonDecode(response.body);
        return {'success': false, 'error': error['message']};
      }
    } catch (error) {
      return {'success': false, 'error': 'Network error'};
    }
  }

  Future<Map<String, dynamic>?> getProfile() async {
    if (_token == null) {
      final prefs = await SharedPreferences.getInstance();
      _token = prefs.getString('authToken');
    }

    if (_token == null) return null;

    try {
      final response = await http.get(
        Uri.parse('$baseUrl/api/mobile/users/profile'),
        headers: {'Authorization': 'Bearer $_token'},
      );

      if (response.statusCode == 200) {
        return jsonDecode(response.body);
      }
    } catch (error) {
      print('Failed to get profile: $error');
    }
    return null;
  }

  Future<bool> validateToken() async {
    if (_token == null) return false;

    try {
      final response = await http.post(
        Uri.parse('$baseUrl/api/mobile/auth/validate'),
        headers: {'Authorization': 'Bearer $_token'},
      );

      return response.statusCode == 200;
    } catch (error) {
      return false;
    }
  }
}
```

## 🎉 What You've Accomplished

✅ **Mobile-Optimized REST API**  
✅ **Extended JWT Token Expiration for Mobile Use**  
✅ **CORS Configuration for Cross-Origin Requests**  
✅ **Enhanced Authentication Endpoints**  
✅ **User Profile Management**  
✅ **Token Validation and Refresh**  
✅ **Mobile App Integration Examples**

## 🚀 Next Steps

### Enhance Your Mobile API
- Add push notification support
- Implement offline data synchronization
- Add file upload for profile pictures
- Create admin management endpoints

### Production Deployment
- Set up PostgreSQL database
- Configure environment variables
- Add rate limiting
- Set up HTTPS/SSL
- Implement monitoring and logging

### Mobile App Development
- **[React Native Integration](https://reactnative.dev/)** - Build cross-platform mobile apps
- **[Flutter Integration](https://flutter.dev/)** - Build native mobile apps
- **[Ionic Integration](https://ionicframework.com/)** - Build hybrid mobile apps

## 🆘 Troubleshooting

### Common Mobile-Specific Issues
- **CORS errors** → Check your CORS configuration and allowed origins
- **Token expiration too short** → Adjust JWT expiration time for mobile use
- **Network timeouts** → Configure appropriate connection timeouts
- **Token storage** → Use secure storage (Keychain, Android Keystore)

### Need Help?
- 📖 [Troubleshooting Guide](../troubleshooting/index.md)
- 💬 [GitHub Discussions](https://github.com/RicardoMorim/Auth-Provider/discussions)

---

🎉 **Congratulations!** You've built a production-ready mobile API backend with Ricardo Auth!
