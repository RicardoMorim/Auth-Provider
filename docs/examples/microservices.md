# Microservices Architecture Example

Learn how to implement Ricardo Auth in a **distributed microservices architecture** with API Gateway, service discovery, and cross-service authentication.

---

> **Breaking Change (v2.0.0):**
> - Authentication now uses secure cookies (`access_token`, `refresh_token`) with `HttpOnly`, `Secure`, and `SameSite` flags by default. You must use HTTPS in production or set `ricardo.auth.cookies.access.secure: false` for local development only.
> - New blocklist and rate limiting features are available (see below).
> - New `/api/auth/revoke` admin endpoint for revoking tokens (access or refresh).

## 📋 Quick Navigation

- [Overview](#overview)
- [Architecture](#architecture)
- [API Gateway Setup](#api-gateway-setup)
- [User Service](#user-service)
- [Auth Service](#auth-service)
- [Service Discovery](#service-discovery)
- [Testing](#testing)

## Overview

**What You'll Build:**
- API Gateway for request routing
- Dedicated Auth Service for authentication
- User Service for user management
- JWT token sharing across services
- Eureka service discovery
- **Token blocklist and rate limiting (optional)**

**Technologies:**
- Spring Cloud Gateway
- Eureka Server
- Ricardo Auth Starter
- PostgreSQL
- Docker (optional)

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Client    │───▶│ API Gateway │───▶│Auth Service │
│ (Frontend)  │    │   :8080     │    │   :8081     │
└─────────────┘    └─────────────┘    └─────────────┘
                           │           
                           ▼           
                   ┌─────────────┐    ┌─────────────┐
                   │User Service │    │   Eureka    │
                   │   :8082     │◄──▶│ Discovery   │
                   └─────────────┘    │   :8761     │
                                      └─────────────┘
```

## API Gateway Setup

### Dependencies (pom.xml)
```xml
<dependencies>
    <!-- Spring Cloud Gateway -->
    <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-starter-gateway</artifactId>
    </dependency>
    
    <!-- Ricardo Auth for JWT validation -->
    <dependency>
        <groupId>io.github.ricardomorim</groupId>
        <artifactId>auth-spring-boot-starter</artifactId>
        <version>1.1.0</version>
    </dependency>
    
    <!-- Service Discovery -->
    <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
    </dependency>
</dependencies>
```

### Gateway Configuration
```yaml
# application-gateway.yml
spring:
  application:
    name: api-gateway
  cloud:
    gateway:
      routes:
        # Auth Service Routes
        - id: auth-service
          uri: lb://auth-service
          predicates:
            - Path=/auth/**
          filters:
            - StripPrefix=1
        
        # User Service Routes (Protected)
        - id: user-service
          uri: lb://user-service
          predicates:
            - Path=/users/**
          filters:
            - StripPrefix=1
            - name: AuthFilter
        
        # Public Health Checks
        - id: health-checks
          uri: lb://user-service
          predicates:
            - Path=/actuator/health
      
      # Global CORS Configuration
      globalcors:
        corsConfigurations:
          '[/**]':
            allowedOrigins: "http://localhost:3000"
            allowedMethods:
              - GET
              - POST
              - PUT
              - DELETE
              - OPTIONS
            allowedHeaders: "*"
            allowCredentials: true

# Ricardo Auth Configuration
ricardo:
  auth:
    jwt:
      secret: ${JWT_SECRET}
    controllers:
      auth:
        enabled: false  # Auth handled by dedicated service
      user:
        enabled: false  # User management handled by dedicated service
    # --- NEW: Blocklist and Rate Limiter ---
    token-blocklist:
      enabled: true
      type: redis   # Use 'redis' for distributed blocklist in production
    rate-limiter:
      enabled: true
      type: redis   # Use 'redis' for distributed rate limiting in production
      max-requests: 200
      time-window-ms: 60000
    # --- NEW: Cookie Security ---
    cookies:
      access:
        secure: true      # Set to false for local dev only
        http-only: true
        same-site: Strict # Strict/Lax/None
        path: /
      refresh:
        secure: true
        http-only: true
        same-site: Strict
        path: /api/auth/refresh
  redirect-https: true   # Enforce HTTPS (recommended for production)

# Eureka Configuration
eureka:
  client:
    service-url:
      defaultZone: http://localhost:8761/eureka/

server:
  port: 8080
```

---

### Token Blocklist and Rate Limiting (NEW)

- **Token Blocklist:**
  - Prevents usage of revoked tokens (access or refresh). Supports in-memory or Redis for distributed setups.
  - Configure with `ricardo.auth.token-blocklist.type: memory|redis`.
- **Rate Limiting:**
  - Protects endpoints from brute-force and abuse. Supports in-memory or Redis for distributed setups.
  - Configure with `ricardo.auth.rate-limiter.type: memory|redis` and set `max-requests` and `time-window-ms`.

---

### Token Revocation Endpoint (NEW)

Ricardo Auth now provides an admin-only endpoint to revoke any token (access or refresh):

```http
POST /api/auth/revoke
Authorization: Bearer <admin-access-token>
Content-Type: application/json

{
  "token": "<token-to-revoke>"
}
```
- Only users with `ADMIN` role can call this endpoint.
- Works for both access and refresh tokens.

---

## User Service

### Enhanced User Controller

```java
package com.mycompany.userservice.controller;

import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.user.User;
import com.ricardo.auth.dto.UserDTO;
import com.ricardo.auth.dto.UserDTOMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class EnhancedUserController {

    private final UserService userService;

    public EnhancedUserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/profile")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<UserDTO> getMyProfile(@RequestHeader("X-User-Email") String userEmail) {
        User user = userService.getUserByEmail(userEmail);
        return ResponseEntity.ok(UserDTOMapper.toDTO(user));
    }

    @PutMapping("/profile")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<UserDTO> updateProfile(
            @RequestHeader("X-User-Email") String userEmail,
            @RequestBody UpdateProfileRequestDTO request) {

        User user = userService.getUserByEmail(userEmail);

        // Update profile fields
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPhoneNumber(request.getPhoneNumber());

        User updatedUser = userService.updateUser(user.getId(), user);
        return ResponseEntity.ok(UserDTOMapper.toDTO(updatedUser));
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

    @GetMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserDTO> getUserById(@PathVariable Long userId) {
        User user = userService.getUserById(userId);
        return ResponseEntity.ok(UserDTOMapper.toDTO(user));
    }
}
```

### User Service Configuration
```yaml
# application-user.yml
spring:
  application:
    name: user-service
  datasource:
    url: jdbc:postgresql://localhost:5432/userdb
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false

# Ricardo Auth Configuration
ricardo:
  auth:
    jwt:
      secret: ${JWT_SECRET}  # Same secret for token validation
    controllers:
      auth:
        enabled: false  # Auth handled by dedicated service
      user:
        enabled: true   # Enable user management endpoints

eureka:
  client:
    service-url:
      defaultZone: http://localhost:8761/eureka/

server:
  port: 8082

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
```

## Service Discovery

### Eureka Server
```java
package com.mycompany.discovery;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;

@SpringBootApplication
@EnableEurekaServer
public class DiscoveryServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(DiscoveryServerApplication.class, args);
    }
}
```

### Eureka Configuration
```yaml
# application-discovery.yml
spring:
  application:
    name: discovery-server

eureka:
  instance:
    hostname: localhost
  client:
    register-with-eureka: false
    fetch-registry: false
    service-url:
      defaultZone: http://${eureka.instance.hostname}:${server.port}/eureka/

server:
  port: 8761

management:
  endpoints:
    web:
      exposure:
        include: health,info
```

## Docker Setup (Optional)

### Docker Compose
```yaml
# docker-compose.yml
version: '3.8'
services:
  discovery:
    build: ./discovery-server
    ports:
      - "8761:8761"
    environment:
      - SPRING_PROFILES_ACTIVE=docker
    
  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=microservices
      - POSTGRES_USER=dbuser
      - POSTGRES_PASSWORD=dbpass
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
  
  auth-service:
    build: ./auth-service
    ports:
      - "8081:8081"
    environment:
      - SPRING_PROFILES_ACTIVE=docker
      - JWT_SECRET=your-production-jwt-secret-key
      - DB_USERNAME=dbuser
      - DB_PASSWORD=dbpass
      - DATABASE_URL=jdbc:postgresql://postgres:5432/microservices
    depends_on:
      - postgres
      - discovery
  
  user-service:
    build: ./user-service
    ports:
      - "8082:8082"
    environment:
      - SPRING_PROFILES_ACTIVE=docker
      - JWT_SECRET=your-production-jwt-secret-key
      - DB_USERNAME=dbuser
      - DB_PASSWORD=dbpass
      - DATABASE_URL=jdbc:postgresql://postgres:5432/microservices
    depends_on:
      - postgres
      - discovery
  
  api-gateway:
    build: ./api-gateway
    ports:
      - "8080:8080"
    environment:
      - SPRING_PROFILES_ACTIVE=docker
      - JWT_SECRET=your-production-jwt-secret-key
    depends_on:
      - discovery
      - auth-service
      - user-service

volumes:
  postgres_data:
```

## Testing

### Integration Test
```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
public class MicroservicesIntegrationTest {
    
    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15")
            .withDatabaseName("testdb")
            .withUsername("test")
            .withPassword("test");
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Test
    public void testFullMicroservicesFlow() {
        // 1. Create user through Gateway -> Auth Service
        CreateUserRequestDTO createRequest = new CreateUserRequestDTO();
        createRequest.setUsername("testuser");
        createRequest.setEmail("test@example.com");
        createRequest.setPassword("TestPassword@123!");
        
        ResponseEntity<UserDTO> createResponse = restTemplate.postForEntity(
            "/auth/users/create", createRequest, UserDTO.class);
        
        assertThat(createResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        
        // 2. Login through Gateway -> Auth Service
        LoginRequestDTO loginRequest = new LoginRequestDTO();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("TestPassword@123!");
        
        ResponseEntity<TokenDTO> loginResponse = restTemplate.postForEntity(
            "/auth/login", loginRequest, TokenDTO.class);
        
        assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        String token = loginResponse.getBody().getToken();
        
        // 3. Access user profile through Gateway -> User Service
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        HttpEntity<Void> entity = new HttpEntity<>(headers);
        
        ResponseEntity<UserDTO> profileResponse = restTemplate.exchange(
            "/users/profile", HttpMethod.GET, entity, UserDTO.class);
        
        assertThat(profileResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(profileResponse.getBody().getEmail()).isEqualTo("test@example.com");
    }
}
```

### Load Testing
```bash
# Install Apache Bench
apt-get install apache2-utils

# Test authentication endpoint
ab -n 1000 -c 10 -p login.json -T application/json http://localhost:8080/auth/login

# Test protected endpoint
ab -n 1000 -c 10 -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8080/users/profile
```

## Monitoring and Observability

### Distributed Tracing
```xml
<!-- Add to all services -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-sleuth</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-sleuth-zipkin</artifactId>
</dependency>
```

### Metrics Collection
```yaml
# Add to all services
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  metrics:
    export:
      prometheus:
        enabled: true
```

## Deployment

### Kubernetes Deployment
```yaml
# k8s-deployment.yml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
    spec:
      containers:
      - name: auth-service
        image: mycompany/auth-service:latest
        ports:
        - containerPort: 8081
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: jwt-secret
        - name: DATABASE_URL
          value: "jdbc:postgresql://postgres:5432/authdb"
---
apiVersion: v1
kind: Service
metadata:
  name: auth-service
spec:
  selector:
    app: auth-service
  ports:
  - port: 8081
    targetPort: 8081
```

This microservices example demonstrates how to build a scalable, distributed authentication system using Ricardo Auth across multiple services with proper service discovery, API gateway routing, and cross-service JWT token validation.
