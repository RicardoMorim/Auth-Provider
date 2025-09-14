# Developer Bean Documentation

## Overview

This document provides comprehensive information about all auto-configured beans, their dependencies, and configurable properties in the Auth Provider Spring Boot Starter.

## 🔧 Auto-Configuration Summary

The Auth Provider automatically configures beans based on:
- **Classpath dependencies** (JPA, Redis, PostgreSQL drivers)
- **Configuration properties** (`ricardo.auth.*`)
- **Conditional annotations** (`@ConditionalOnProperty`, `@ConditionalOnClass`, etc.)

All configuration is handled by `AuthAutoConfiguration.class`.

---

## 📦 Core Beans

### 1. JwtService Bean

**Class**: `JwtServiceImpl`  
**Purpose**: JWT token generation, validation, and parsing  
**Condition**: Always created when auth is enabled

**Dependencies**:
- `AuthProperties authProperties` - JWT configuration (secret, expiration times)

**Configurable Properties**:
```yaml
ricardo:
  auth:
    jwt:
      secret: "your-base64-secret-key"           # Required - Base64 encoded secret
      access-token-expiration: 900000           # 15 minutes (milliseconds)
      refresh-token-expiration: 604800000       # 7 days (milliseconds)
```

**Bean Creation**:
```java
@Bean
@ConditionalOnMissingBean
public JwtService jwtService(AuthProperties authProperties) {
    return new JwtServiceImpl(authProperties);
}
```

---

### 2. UserService Bean

**Class**: `UserServiceImpl<User, AppRole, UUID>`  
**Purpose**: User CRUD operations and business logic  
**Condition**: Always created when auth is enabled

**Dependencies**:
- `UserRepository<User, AppRole, UUID> userRepository` - Data access layer
- `EventPublisher eventPublisher` - Domain event publishing

**Configurable Properties**:
```yaml
ricardo:
  auth:
    repository:
      type: JPA  # or POSTGRESQL for direct SQL
```

**Bean Creation**:
```java
@Bean
@ConditionalOnMissingBean
public UserService<User, AppRole, UUID> userService(
    UserRepository<User, AppRole, UUID> userRepository, 
    EventPublisher eventPublisher) {
    return new UserServiceImpl<>(userRepository, eventPublisher);
}
```

---

### 3. RefreshTokenService Bean

**Class**: `RefreshTokenServiceImpl<User, AppRole, UUID>`  
**Purpose**: Refresh token lifecycle management  
**Condition**: `ricardo.auth.refresh-tokens.enabled=true` (default: true)

**Dependencies**:
- `RefreshTokenRepository refreshTokenRepository` - Token storage
- `UserService<User, AppRole, UUID> userService` - User operations
- `AuthProperties authProperties` - Token configuration

**Configurable Properties**:
```yaml
ricardo:
  auth:
    refresh-tokens:
      enabled: true                    # Enable/disable refresh tokens
      max-tokens-per-user: 5          # Maximum tokens per user (0 = unlimited)
      rotate-on-refresh: true         # Generate new token on refresh
      cleanup-interval: 3600000       # Auto-cleanup interval (1 hour)
      auto-cleanup: true              # Enable automatic expired token cleanup
```

**Bean Creation**:
```java
@Bean
@ConditionalOnMissingBean
@ConditionalOnProperty(prefix = "ricardo.auth.refresh-tokens", name = "enabled", havingValue = "true", matchIfMissing = true)
public RefreshTokenService<User, AppRole, UUID> refreshTokenService(
    RefreshTokenRepository refreshTokenRepository,
    UserService<User, AppRole, UUID> userService,
    AuthProperties authProperties) {
    return new RefreshTokenServiceImpl<>(refreshTokenRepository, userService, authProperties);
}
```

---

### 4. JwtAuthFilter Bean

**Class**: `JwtAuthFilter`  
**Purpose**: JWT authentication filter for request processing  
**Condition**: Always created when auth is enabled

**Dependencies**:
- `JwtService jwtService` - Token validation
- `TokenBlocklist tokenBlocklist` - Token revocation checking
- `AuthProperties authProperties` - Cookie and security configuration

**Configurable Properties**:
```yaml
ricardo:
  auth:
    cookies:
      access:
        secure: true          # HTTPS-only cookies
        http-only: true       # Prevent JavaScript access
        same-site: Strict     # CSRF protection
        path: /               # Cookie path
    token-blocklist:
      enabled: true           # Enable token revocation
      type: memory           # memory or redis
```

**Bean Creation**:
```java
@Bean
@ConditionalOnMissingBean
public JwtAuthFilter jwtAuthFilter(
    JwtService jwtService, 
    TokenBlocklist tokenBlocklist, 
    AuthProperties authProperties) {
    return new JwtAuthFilter(jwtService, tokenBlocklist, authProperties);
}
```

---

### 5. PasswordPolicyService Bean

**Class**: `PasswordPolicy`  
**Purpose**: Password validation and policy enforcement  
**Condition**: Always created when auth is enabled

**Dependencies**:
- `AuthProperties authProperties` - Password policy configuration

**Configurable Properties**:
```yaml
ricardo:
  auth:
    password-policy:
      min-length: 8                                    # Minimum password length
      max-length: 128                                  # Maximum password length
      require-uppercase: true                          # Require uppercase letters
      require-lowercase: true                          # Require lowercase letters
      require-digits: true                             # Require numeric digits
      require-special-chars: false                     # Require special characters
      allowed-special-chars: "!@#$%^&*()_+-=[]{}|;:,.<>?"  # Allowed special chars
      prevent-common-passwords: true                   # Block common passwords
      common-passwords-file-path: "/commonpasswords.txt"    # Common passwords file
```

**Bean Creation**:
```java
@Bean
@ConditionalOnMissingBean
public PasswordPolicyService passwordPolicyService(AuthProperties authProperties) {
    return new PasswordPolicy(authProperties);
}
```

---

## 🏛️ Repository Beans (Conditional)

### JPA Repository Configuration

**Condition**: `ricardo.auth.repository.type=JPA` (default)

**Auto-Created Beans**:
- `DefaultUserJpaRepository` - JPA user repository
- `DefaultJpaRefreshTokenRepository` - JPA refresh token repository  
- `DefaultJpaPasswordResetTokenRepository` - JPA password reset repository

**Dependencies**: Standard JPA/Hibernate setup

**Configurable Properties**:
```yaml
spring:
  datasource:
    url: jdbc:h2:mem:testdb       # Database connection
    driver-class-name: org.h2.Driver
  jpa:
    hibernate:
      ddl-auto: create-drop       # Schema management
    show-sql: false               # SQL logging
```

### PostgreSQL Repository Configuration

**Condition**: `ricardo.auth.repository.type=POSTGRESQL`

**Auto-Created Beans**:
- `UserPostgreSQLRepository` - Direct SQL user repository
- `PostgreSQLRefreshTokenRepository` - Direct SQL refresh token repository
- `PostgreSqlPasswordResetTokenRepository` - Direct SQL password reset repository

**Dependencies**:
- `DataSource dataSource` - PostgreSQL connection
- `UserRowMapper<User, AppRole, UUID> userRowMapper` - SQL result mapping
- `UserSqlParameterMapper<User> userSqlParameterMapper` - Parameter mapping
- `RoleMapper<AppRole> roleMapper` - Role conversion
- `IdConverter<UUID> idConverter` - ID conversion

**Configurable Properties**:
```yaml
ricardo:
  auth:
    repository:
      type: POSTGRESQL
      database:
        refresh-tokens-table: "refresh_tokens"        # Table names
        password-reset-tokens-table: "password_reset_tokens"
        schema: "public"                              # Database schema

spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/authdb
    username: your_username
    password: your_password
    driver-class-name: org.postgresql.Driver
```

---

## 🔄 Rate Limiter Beans (Conditional)

### Memory Rate Limiter

**Class**: `InMemoryRateLimiter`  
**Condition**: `ricardo.auth.rate-limiter.type=memory` (default)

**Dependencies**:
- `AuthProperties authProperties` - Rate limiting configuration

**Configurable Properties**:
```yaml
ricardo:
  auth:
    rate-limiter:
      enabled: true              # Enable rate limiting
      type: memory              # In-memory storage
      max-requests: 150         # Maximum requests per time window
      time-window-ms: 60000     # Time window in milliseconds (1 minute)
```

### Redis Rate Limiter

**Class**: `RedisRateLimiter`  
**Condition**: `ricardo.auth.rate-limiter.type=redis` + Redis on classpath

**Dependencies**:
- `RedisTemplate<String, String> redisTemplate` - Redis operations
- `AuthProperties authProperties` - Rate limiting configuration

**Configurable Properties**:
```yaml
ricardo:
  auth:
    rate-limiter:
      enabled: true
      type: redis               # Redis-based storage
      max-requests: 150
      time-window-ms: 60000
    redis:
      host: localhost           # Redis server host
      port: 6379               # Redis server port
      password: ""             # Redis password (optional)
      database: 0              # Redis database number
```

---

## 🚫 Token Blocklist Beans (Conditional)

### Memory Token Blocklist

**Class**: `InMemoryTokenBlocklist`  
**Condition**: Default when no other blocklist is configured

**Dependencies**:
- `AuthProperties authProperties` - Blocklist configuration

**Configurable Properties**:
```yaml
ricardo:
  auth:
    token-blocklist:
      enabled: true              # Enable token revocation
      type: memory              # In-memory storage (default)
```

### Redis Token Blocklist

**Class**: `RedisTokenBlockList`  
**Condition**: `ricardo.auth.token-blocklist.type=redis` + Redis on classpath

**Dependencies**:
- `RedisTemplate<String, String> redisTemplate` - Redis operations
- `AuthProperties authProperties` - Blocklist configuration

**Configurable Properties**:
```yaml
ricardo:
  auth:
    token-blocklist:
      enabled: true
      type: redis               # Redis-based storage
    redis:
      host: localhost
      port: 6379
      password: ""
      database: 0
```

---

## 🎮 Controller Beans (Conditional)

### AuthController Bean

**Class**: `AuthController<User, AppRole, UUID>`  
**Purpose**: Authentication endpoints (login, refresh, logout, me)  
**Condition**: `ricardo.auth.controllers.auth.enabled=true` (default)

**Dependencies**:
- `JwtService jwtService` - Token operations
- `AuthenticationManager authManager` - Spring Security authentication
- `RefreshTokenService<User, AppRole, UUID> refreshTokenService` - Token refresh
- `AuthProperties authProperties` - Configuration
- `TokenBlocklist tokenBlocklist` - Token revocation

**Configurable Properties**:
```yaml
ricardo:
  auth:
    controllers:
      auth:
        enabled: true           # Enable AuthController endpoints
```

### UserController Bean

**Class**: `UserController<User, AppRole, UUID>`  
**Purpose**: User management endpoints (CRUD operations)  
**Condition**: `ricardo.auth.controllers.user.enabled=true` (default)

**Dependencies**:
- `UserService<User, AppRole, UUID> userService` - User operations
- `AuthUserFactory<User, AppRole, UUID> userBuilder` - User creation
- `IdConverter<UUID> idConverter` - ID conversion

**Configurable Properties**:
```yaml
ricardo:
  auth:
    controllers:
      user:
        enabled: true           # Enable UserController endpoints
```

---

## 🔐 Security Beans

### SecurityConfig Beans

**Auto-Created Beans**:
- `PasswordEncoder` - BCrypt password encoder
- `AuthenticationManager` - Spring Security authentication manager
- `AuthenticationEntryPoint` - Custom 401 response handler
- `CorsConfigurationSource` - CORS configuration for cross-origin requests
- `SecurityFilterChain` - Complete security configuration

**Dependencies**: Spring Security framework

**Configurable Properties**:
```yaml
ricardo:
  auth:
    redirect-https: true        # Force HTTPS redirect

# CORS can be customized via Spring Boot properties
spring:
  web:
    cors:
      allowed-origin-patterns: "https://app.example.com,https://admin.example.com"
      allow-credentials: true
```

---

## 🛠️ Utility Beans

### IdConverter Bean

**Class**: `UUIDIdConverter`  
**Purpose**: String to UUID conversion for path parameters  
**Condition**: Always created when no custom converter exists

### UserRowMapper Bean

**Class**: Custom implementation  
**Purpose**: Map SQL ResultSet to User objects (PostgreSQL mode)  
**Condition**: PostgreSQL repository type

### RoleMapper Bean

**Class**: `AppRoleMapper`  
**Purpose**: Convert between role strings and AppRole enums  
**Condition**: Always created when no custom mapper exists

### AuthUserFactory Bean

**Class**: `UserFactory`  
**Purpose**: Create User entities with proper validation  
**Condition**: Always created when no custom factory exists

**Dependencies**:
- `PasswordPolicyService passwordPolicyService` - Password validation
- `PasswordEncoder passwordEncoder` - Password hashing

---

## 📋 Configuration Properties Reference

### Complete Configuration Example

```yaml
ricardo:
  auth:
    enabled: true                                    # Master enable/disable switch
    redirect-https: true                            # Force HTTPS redirect
    
    jwt:
      secret: "your-256-bit-base64-encoded-secret"  # Required - JWT signing key
      access-token-expiration: 900000               # 15 minutes
      refresh-token-expiration: 604800000           # 7 days
    
    controllers:
      auth:
        enabled: true                               # Enable auth endpoints
      user:
        enabled: true                               # Enable user management
    
    password-policy:
      min-length: 8
      max-length: 128
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: false
      prevent-common-passwords: true
    
    refresh-tokens:
      enabled: true
      max-tokens-per-user: 5
      rotate-on-refresh: true
      auto-cleanup: true
      cleanup-interval: 3600000
    
    rate-limiter:
      enabled: true
      type: memory                                  # memory or redis
      max-requests: 150
      time-window-ms: 60000
    
    token-blocklist:
      enabled: true
      type: memory                                  # memory or redis
    
    cookies:
      access:
        secure: true                                # HTTPS-only
        http-only: true                             # XSS protection
        same-site: Strict                           # CSRF protection
        path: /
      refresh:
        secure: true
        http-only: true
        same-site: Strict
        path: /api/auth/refresh
    
    repository:
      type: JPA                                     # JPA or POSTGRESQL
    
    redis:                                          # Required if using Redis features
      host: localhost
      port: 6379
      password: ""
      database: 0
    
    password-reset:
      enabled: true
      token-expiry-hours: 1
      max-attempts-per-hour: 3
      max-attempts-per-ip-per-hour: 10
    
    email:
      from-address: "noreply@example.com"
      from-name: "Auth Service"
    
    role-management:
      enable-role-events: true
      require-admin-for-role-changes: true
      allow-self-role-modification: false
```

---

## 🔍 Bean Inspection

### View All Auto-Configured Beans

Add this to your `application.yml` for debugging:

```yaml
logging:
  level:
    com.ricardo.auth.autoconfig: DEBUG
    org.springframework.boot.autoconfigure: DEBUG

# Enable actuator to view beans
management:
  endpoints:
    web:
      exposure:
        include: beans,conditions
```

Access via:
- `GET /actuator/beans` - All Spring beans
- `GET /actuator/conditions` - Auto-configuration conditions

### Custom Bean Override

To override any auto-configured bean, simply create your own:

```java
@Configuration
public class CustomAuthConfig {
    
    @Bean
    @Primary  // Takes precedence over auto-configured bean
    public UserService<User, AppRole, UUID> customUserService(
        UserRepository<User, AppRole, UUID> repository,
        EventPublisher eventPublisher) {
        return new MyCustomUserService(repository, eventPublisher);
    }
}
```

---

## 📖 Related Documentation

- [Configuration Guide](configuration/index.md)
- [Security Guide](security-guide.md)
- [API Documentation](swagger-api-documentation.md)
- [Cookie Authentication Guide](cookie-authentication-guide.md)
