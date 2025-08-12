# Multi-Tenant Application Example

Build a **multi-tenant SaaS application** with Ricardo Auth, featuring tenant isolation, custom user roles, and
tenant-specific configurations.

---
> **Breaking Changes (v3.0.0):**
> - **UUID Primary Keys:** All user IDs are now UUID instead of Long. Update entity IDs, repository generics, DTOs, controller path variables, and service signatures to use `UUID`.
> - **Enhanced Decoupling:** New factory pattern for user creation
> - **Repository Types:** Choose between JPA and PostgreSQL implementations
> - **CSRF Protection:** Cross-Site Request Forgery protection now enabled by default (NEW)
>
> **v2.0.0 Changes:**
> - Authentication now uses secure cookies (`access_token`, `refresh_token`) with `HttpOnly`, `Secure`, and `SameSite`
>     flags by default. You must use HTTPS in production or set `ricardo.auth.cookies.access.secure: false` for local
>     development only.
> - New blocklist and rate limiting features are available (see below).
> - New `/api/auth/revoke` admin endpoint for revoking tokens (access or refresh).

## 📋 Quick Navigation

- [Overview](#overview)
- [Tenant Architecture](#tenant-architecture)
- [Tenant Resolution](#tenant-resolution)
- [Tenant-Aware User Management](#tenant-aware-user-management)
- [Data Isolation](#data-isolation)
- [Tenant Configuration](#tenant-configuration)
- [Admin Panel](#admin-panel)
- [Testing](#testing)

## Overview

**What You'll Build:**

- Multi-tenant SaaS platform
- Tenant-based data isolation
- Custom roles per tenant
- Tenant configuration management
- Admin panel for tenant management
- Tenant-specific branding and settings

**Features:**

- Database-per-tenant or schema-per-tenant
- Tenant resolution from domain/header/path
- Tenant-specific user roles and permissions
- Isolated user data per tenant
- Centralized tenant administration

## Tenant Architecture

### Architecture Options

**1. Database Per Tenant (Recommended for high isolation)**

```
Tenant A ──► Database A (tenant_a_db)
Tenant B ──► Database B (tenant_b_db)  
Tenant C ──► Database C (tenant_c_db)
```

**2. Schema Per Tenant (Balanced approach)**

```
Shared Database
├── tenant_a_schema
├── tenant_b_schema
└── tenant_c_schema
```

**3. Row-Level Security (Cost-effective)**

```
Shared Database + Shared Schema
Users table: tenant_id column for isolation
```

## Project Setup

### Dependencies (pom.xml)

```xml
<dependencies>
    <!-- Ricardo Auth Starter -->
    <dependency>
        <groupId>io.github.ricardomorim</groupId>
        <artifactId>auth-spring-boot-starter</artifactId>
        <version>1.2.0</version>
    </dependency>
    <!-- Redis for blocklist/rate limiting (optional) -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-redis</artifactId>
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
    
    <!-- Multi-tenancy support -->
    <dependency>
        <groupId>org.hibernate</groupId>
        <artifactId>hibernate-core</artifactId>
    </dependency>
    
    <!-- PostgreSQL -->
    <dependency>
        <groupId>org.postgresql</groupId>
        <artifactId>postgresql</artifactId>
        <scope>runtime</scope>
    </dependency>
    
    <!-- Redis for tenant caching -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-redis</artifactId>
    </dependency>
</dependencies>
```

### Configuration

```yaml
# application.yml
spring:
  application:
    name: multi-tenant-app
  
  # Master database for tenant metadata
  datasource:
    master:
      url: jdbc:postgresql://localhost:5432/master_db
      username: ${MASTER_DB_USERNAME}
      password: ${MASTER_DB_PASSWORD}
      driver-class-name: org.postgresql.Driver
  
  # JPA Configuration
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false
    database-platform: org.hibernate.dialect.PostgreSQLDialect
  
  # Redis for tenant caching
  redis:
    host: localhost
    port: 6379
    password: ${REDIS_PASSWORD:}

# Ricardo Auth Configuration
ricardo:
  auth:
    jwt:
      secret: ${JWT_SECRET}
      access-token-expiration: 3600000  # 1 hour for multi-tenant security
      refresh-token-expiration: 2592000000 # 30 days for refresh tokens
    controllers:
      auth:
        enabled: true
      user:
        enabled: true
    password-policy:
      min-length: 10
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      prevent-common-passwords: true
    token-blocklist:
      enabled: true
      type: redis   # or 'memory' for dev
    rate-limiter:
      enabled: true
      type: redis   # or 'memory' for dev
      max-requests: 200
      time-window-ms: 60000
    cookies:
      access:
        secure: true
        httpOnly: true
        sameSite: Strict
        path: /
      refresh:
        secure: true
        httpOnly: true
        sameSite: Strict
        path: /api/auth/refresh
    redirect-https: true

# Multi-tenant configuration
app:
  multi-tenant:
    strategy: SCHEMA  # DATABASE, SCHEMA, or ROW_LEVEL
    default-tenant: system
    tenant-cache-ttl: 300

server:
  port: 8080

logging:
  level:
    com.mycompany.multitenant: INFO
    org.hibernate.SQL: DEBUG
```

# ⚠️ Breaking Changes in v1.2.0

- **Token cookies**: Authentication now uses secure cookies for access and refresh tokens, with `httpOnly`, `secure`,
  and `sameSite` flags by default. Update your frontend to use cookies for authentication.
- **HTTPS enforcement**: By default, the API only allows HTTPS. To disable, set `ricardo.auth.redirect-https=false`.
- **Blocklist support**: Add `ricardo.auth.token-blocklist` config to enable in-memory or Redis-based token revocation.
- **Rate limiting**: Add `ricardo.auth.rate-limiter` config for in-memory or Redis-based rate limiting.
- **/api/auth/revoke endpoint**: New admin-only endpoint to revoke any access or refresh token.

## Tenant Resolution

### Tenant Resolver Interface

```java
package com.mycompany.multitenant.tenant;

import jakarta.servlet.http.HttpServletRequest;

public interface TenantResolver {
    String resolveTenant(HttpServletRequest request);
}
```

### Multiple Resolution Strategies

```java
// 1. Domain-based resolution (e.g., tenant1.myapp.com)
@Component
public class DomainTenantResolver implements TenantResolver {
    
    @Override
    public String resolveTenant(HttpServletRequest request) {
        String serverName = request.getServerName();
        
        if (serverName.contains(".")) {
            String[] parts = serverName.split("\\.");
            if (parts.length >= 3) {
                return parts[0]; // Extract subdomain as tenant
            }
        }
        
        return "default";
    }
}

// 2. Header-based resolution (X-Tenant-ID header)
@Component
public class HeaderTenantResolver implements TenantResolver {
    
    @Override
    public String resolveTenant(HttpServletRequest request) {
        String tenantId = request.getHeader("X-Tenant-ID");
        
        if (tenantId == null || tenantId.isEmpty()) {
            throw new IllegalArgumentException("Tenant ID is required in X-Tenant-ID header");
        }
        
        return tenantId;
    }
}

// 3. Path-based resolution (e.g., /tenant1/api/users)
@Component
public class PathTenantResolver implements TenantResolver {
    
    @Override
    public String resolveTenant(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        
        if (requestURI.startsWith("/")) {
            String[] pathParts = requestURI.split("/");
            if (pathParts.length >= 2) {
                return pathParts[1]; // First path segment as tenant
            }
        }
        
        return "default";
    }
}

// 4. Composite resolver (tries multiple strategies)
@Component
@Primary
public class CompositeTenantResolver implements TenantResolver {
    
    private final List<TenantResolver> resolvers;
    
    public CompositeTenantResolver() {
        this.resolvers = Arrays.asList(
            new DomainTenantResolver(),
            new HeaderTenantResolver(),
            new PathTenantResolver()
        );
    }
    
    @Override
    public String resolveTenant(HttpServletRequest request) {
        for (TenantResolver resolver : resolvers) {
            try {
                String tenant = resolver.resolveTenant(request);
                if (tenant != null && !tenant.isEmpty() && !"default".equals(tenant)) {
                    return tenant;
                }
            } catch (Exception e) {
                // Continue to next resolver
            }
        }
        
        return "default";
    }
}
```

### Tenant Context

```java
package com.mycompany.multitenant.context;

public class TenantContext {
    
    private static final ThreadLocal<String> CURRENT_TENANT = new ThreadLocal<>();
    
    public static void setCurrentTenant(String tenant) {
        CURRENT_TENANT.set(tenant);
    }
    
    public static String getCurrentTenant() {
        return CURRENT_TENANT.get();
    }
    
    public static void clear() {
        CURRENT_TENANT.remove();
    }
}
```

### Tenant Interceptor

```java
@Component
public class TenantInterceptor implements HandlerInterceptor {
    
    private final TenantResolver tenantResolver;
    private final TenantService tenantService;
    
    public TenantInterceptor(TenantResolver tenantResolver, TenantService tenantService) {
        this.tenantResolver = tenantResolver;
        this.tenantService = tenantService;
    }
    
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String tenantId = tenantResolver.resolveTenant(request);
        
        // Validate tenant exists and is active
        if (!tenantService.isTenantValid(tenantId)) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            return false;
        }
        
        // Set tenant context
        TenantContext.setCurrentTenant(tenantId);
        return true;
    }
    
    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, 
                              Object handler, Exception ex) {
        TenantContext.clear();
    }
}
```

## Tenant-Aware User Management

### Tenant Entity

```java
@Entity
@Table(name = "tenants")
public class Tenant {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "tenant_id", unique = true, nullable = false)
    private String tenantId;
    
    @Column(name = "name", nullable = false)
    private String name;
    
    @Column(name = "domain")
    private String domain;
    
    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    private TenantStatus status = TenantStatus.ACTIVE;
    
    @Column(name = "database_url")
    private String databaseUrl;
    
    @Column(name = "schema_name")
    private String schemaName;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();
    
    @Column(name = "expires_at")
    private LocalDateTime expiresAt;
    
    @Column(name = "settings", columnDefinition = "jsonb")
    private String settings; // JSON configuration
    
    // Getters and setters...
}

public enum TenantStatus {
    ACTIVE, SUSPENDED, EXPIRED, DELETED
}
```

### Tenant-Aware User Entity

```java
@Entity
@Table(name = "tenant_users")
@FilterDef(name = "tenantFilter", parameters = @ParamDef(name = "tenantId", type = String.class))
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
public class TenantUser extends User {
    
    @Column(name = "tenant_id", nullable = false)
    private String tenantId;
    
    @Column(name = "tenant_role")
    private String tenantRole; // TENANT_ADMIN, TENANT_USER, etc.
    
    @Column(name = "tenant_permissions", columnDefinition = "jsonb")
    private String tenantPermissions; // JSON array of permissions
    
    @Column(name = "department")
    private String department;
    
    @Column(name = "employee_id")
    private String employeeId;
    
    @Column(name = "is_tenant_admin")
    private Boolean isTenantAdmin = false;
    
    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;
    
    // Constructors, getters, and setters...
    
    public TenantUser() {}
    
    public TenantUser(String tenantId, String username, String email, String password) {
        super(Username.valueOf(username), Email.valueOf(email), Password.valueOf(password, passwordEncoder));
        this.tenantId = tenantId;
    }
}
```

### Tenant-Aware User Service

```java
@Service
@Transactional
public class TenantAwareUserService extends UserServiceImpl {
    
    private final TenantUserRepository tenantUserRepository;
    private final TenantService tenantService;
    
    @Override
    public User createUser(User user) {
        String tenantId = TenantContext.getCurrentTenant();
        
        if (tenantId == null) {
            throw new IllegalStateException("Tenant context not set");
        }
        
        // Validate tenant
        if (!tenantService.isTenantActive(tenantId)) {
            throw new TenantInactiveException("Tenant is not active: " + tenantId);
        }
        
        // Check tenant user limit
        if (tenantService.isUserLimitReached(tenantId)) {
            throw new TenantUserLimitExceededException("User limit reached for tenant: " + tenantId);
        }
        
        TenantUser tenantUser = new TenantUser(
            tenantId,
            user.getUsername().getValue(),
            user.getEmail().getValue(),
            user.getPassword().getValue()
        );
        
        // Set default tenant role
        tenantUser.setTenantRole("TENANT_USER");
        
        return tenantUserRepository.save(tenantUser);
    }
    
    @Override
    public User getUserByEmail(String email) {
        String tenantId = TenantContext.getCurrentTenant();
        
        return tenantUserRepository.findByEmailAndTenantId(email, tenantId)
            .orElseThrow(() -> new UserNotFoundException("User not found: " + email));
    }
    
    @Override
    public Page<User> getAllUsers(Pageable pageable) {
        String tenantId = TenantContext.getCurrentTenant();
        return tenantUserRepository.findByTenantId(tenantId, pageable);
    }
    
    public User assignTenantRole(Long userId, String role) {
        String tenantId = TenantContext.getCurrentTenant();
        
        TenantUser user = tenantUserRepository.findByIdAndTenantId(userId, tenantId)
            .orElseThrow(() -> new UserNotFoundException("User not found: " + userId));
        
        user.setTenantRole(role);
        return tenantUserRepository.save(user);
    }
    
    public User promoteToTenantAdmin(Long userId) {
        String tenantId = TenantContext.getCurrentTenant();
        
        TenantUser user = tenantUserRepository.findByIdAndTenantId(userId, tenantId)
            .orElseThrow(() -> new UserNotFoundException("User not found: " + userId));
        
        user.setIsTenantAdmin(true);
        user.setTenantRole("TENANT_ADMIN");
        
        return tenantUserRepository.save(user);
    }
}
```

## Data Isolation

### Database Per Tenant Configuration

```java
@Configuration
public class MultiTenantDataSourceConfig {
    
    @Bean
    @Primary
    public DataSource dataSource() {
        return new TenantAwareDataSource();
    }
    
    @Bean
    public LocalContainerEntityManagerFactoryBean entityManagerFactory(DataSource dataSource) {
        LocalContainerEntityManagerFactoryBean em = new LocalContainerEntityManagerFactoryBean();
        em.setDataSource(dataSource);
        em.setPackagesToScan("com.mycompany.multitenant.entity");
        
        HibernateJpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
        em.setJpaVendorAdapter(vendorAdapter);
        
        Properties properties = new Properties();
        properties.put("hibernate.hbm2ddl.auto", "validate");
        properties.put("hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect");
        properties.put("hibernate.multiTenancy", "DATABASE");
        properties.put("hibernate.tenant_identifier_resolver", tenantIdentifierResolver());
        properties.put("hibernate.multi_tenant_connection_provider", multiTenantConnectionProvider());
        
        em.setJpaProperties(properties);
        return em;
    }
    
    @Bean
    public CurrentTenantIdentifierResolver tenantIdentifierResolver() {
        return new TenantIdentifierResolver();
    }
    
    @Bean
    public MultiTenantConnectionProvider multiTenantConnectionProvider() {
        return new TenantAwareConnectionProvider();
    }
}

// Tenant-aware DataSource
public class TenantAwareDataSource implements DataSource {
    
    private final Map<String, DataSource> dataSources = new ConcurrentHashMap<>();
    private final TenantService tenantService;
    
    @Override
    public Connection getConnection() throws SQLException {
        String tenantId = TenantContext.getCurrentTenant();
        
        if (tenantId == null) {
            throw new SQLException("No tenant context set");
        }
        
        return getDataSourceForTenant(tenantId).getConnection();
    }
    
    private DataSource getDataSourceForTenant(String tenantId) {
        return dataSources.computeIfAbsent(tenantId, this::createDataSourceForTenant);
    }
    
    private DataSource createDataSourceForTenant(String tenantId) {
        Tenant tenant = tenantService.getTenantById(tenantId);
        
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(tenant.getDatabaseUrl());
        config.setUsername(tenant.getDatabaseUsername());
        config.setPassword(tenant.getDatabasePassword());
        config.setMaximumPoolSize(10);
        config.setMinimumIdle(2);
        
        return new HikariDataSource(config);
    }
}
```

### Schema Per Tenant Configuration

```java
@Component
public class SchemaTenantIdentifierResolver implements CurrentTenantIdentifierResolver {
    
    @Override
    public String resolveCurrentTenantIdentifier() {
        String tenantId = TenantContext.getCurrentTenant();
        return tenantId != null ? "tenant_" + tenantId : "public";
    }
    
    @Override
    public boolean validateExistingCurrentSessions() {
        return true;
    }
}

@Component  
public class SchemaMultiTenantConnectionProvider implements MultiTenantConnectionProvider {
    
    private final DataSource dataSource;
    
    @Override
    public Connection getAnyConnection() throws SQLException {
        return dataSource.getConnection();
    }
    
    @Override
    public Connection getConnection(String tenantIdentifier) throws SQLException {
        Connection connection = getAnyConnection();
        connection.setSchema(tenantIdentifier);
        return connection;
    }
    
    @Override
    public void releaseConnection(String tenantIdentifier, Connection connection) throws SQLException {
        connection.setSchema("public"); // Reset to default
        connection.close();
    }
}
```

### Repository Layer

```java
@Repository
public interface TenantUserRepository extends JpaRepository<TenantUser, Long> {
    
    Optional<TenantUser> findByEmailAndTenantId(String email, String tenantId);
    
    Page<TenantUser> findByTenantId(String tenantId, Pageable pageable);
    
    Optional<TenantUser> findByIdAndTenantId(Long id, String tenantId);
    
    List<TenantUser> findByTenantIdAndTenantRole(String tenantId, String tenantRole);
    
    @Query("SELECT COUNT(u) FROM TenantUser u WHERE u.tenantId = :tenantId")
    long countByTenantId(@Param("tenantId") String tenantId);
    
    @Modifying
    @Query("UPDATE TenantUser u SET u.lastLoginAt = :loginTime WHERE u.id = :userId AND u.tenantId = :tenantId")
    void updateLastLoginTime(@Param("userId") Long userId, 
                           @Param("tenantId") String tenantId, 
                           @Param("loginTime") LocalDateTime loginTime);
}
```

## Tenant Configuration

### Tenant Service

```java
@Service
@Transactional
public class TenantService {
    
    private final TenantRepository tenantRepository;
    private final TenantConfigRepository tenantConfigRepository;
    private final RedisTemplate<String, Object> redisTemplate;
    
    public Tenant createTenant(CreateTenantRequestDTO request) {
        // Validate tenant ID availability
        if (tenantRepository.existsByTenantId(request.getTenantId())) {
            throw new TenantAlreadyExistsException("Tenant already exists: " + request.getTenantId());
        }
        
        Tenant tenant = new Tenant();
        tenant.setTenantId(request.getTenantId());
        tenant.setName(request.getName());
        tenant.setDomain(request.getDomain());
        tenant.setStatus(TenantStatus.ACTIVE);
        
        // Set up tenant database/schema
        setupTenantDatabase(tenant, request.getDatabaseStrategy());
        
        Tenant savedTenant = tenantRepository.save(tenant);
        
        // Create default tenant configuration
        createDefaultTenantConfig(savedTenant);
        
        // Initialize tenant database schema
        initializeTenantSchema(savedTenant);
        
        return savedTenant;
    }
    
    public boolean isTenantValid(String tenantId) {
        // Check cache first
        String cacheKey = "tenant:valid:" + tenantId;
        Boolean cached = (Boolean) redisTemplate.opsForValue().get(cacheKey);
        
        if (cached != null) {
            return cached;
        }
        
        // Check database
        boolean isValid = tenantRepository.existsByTenantIdAndStatus(tenantId, TenantStatus.ACTIVE);
        
        // Cache result
        redisTemplate.opsForValue().set(cacheKey, isValid, 5, TimeUnit.MINUTES);
        
        return isValid;
    }
    
    public boolean isUserLimitReached(String tenantId) {
        Tenant tenant = getTenantById(tenantId);
        TenantConfig config = getTenantConfig(tenantId);
        
        if (config.getMaxUsers() == null) {
            return false; // No limit
        }
        
        long currentUserCount = tenantUserRepository.countByTenantId(tenantId);
        return currentUserCount >= config.getMaxUsers();
    }
    
    public TenantConfig getTenantConfig(String tenantId) {
        String cacheKey = "tenant:config:" + tenantId;
        TenantConfig cached = (TenantConfig) redisTemplate.opsForValue().get(cacheKey);
        
        if (cached != null) {
            return cached;
        }
        
        TenantConfig config = tenantConfigRepository.findByTenantId(tenantId)
            .orElseThrow(() -> new TenantConfigNotFoundException("Config not found for tenant: " + tenantId));
        
        redisTemplate.opsForValue().set(cacheKey, config, 10, TimeUnit.MINUTES);
        return config;
    }
    
    public TenantConfig updateTenantConfig(String tenantId, TenantConfigUpdateDTO update) {
        TenantConfig config = getTenantConfig(tenantId);
        
        // Update configuration
        if (update.getMaxUsers() != null) {
            config.setMaxUsers(update.getMaxUsers());
        }
        if (update.getSettings() != null) {
            config.setSettings(update.getSettings());
        }
        if (update.getFeatures() != null) {
            config.setFeatures(update.getFeatures());
        }
        
        TenantConfig saved = tenantConfigRepository.save(config);
        
        // Invalidate cache
        redisTemplate.delete("tenant:config:" + tenantId);
        
        return saved;
    }
    
    private void setupTenantDatabase(Tenant tenant, DatabaseStrategy strategy) {
        switch (strategy) {
            case DATABASE_PER_TENANT:
                String dbUrl = createTenantDatabase(tenant.getTenantId());
                tenant.setDatabaseUrl(dbUrl);
                break;
            case SCHEMA_PER_TENANT:
                String schemaName = "tenant_" + tenant.getTenantId();
                createTenantSchema(schemaName);
                tenant.setSchemaName(schemaName);
                break;
            case ROW_LEVEL_SECURITY:
                // No additional setup needed
                break;
        }
    }
}
```

### Tenant Configuration Entity

```java
@Entity
@Table(name = "tenant_configs")
public class TenantConfig {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "tenant_id", nullable = false, unique = true)
    private String tenantId;
    
    @Column(name = "max_users")
    private Integer maxUsers;
    
    @Column(name = "max_storage_gb")
    private Integer maxStorageGb;
    
    @Column(name = "features", columnDefinition = "jsonb")
    private String features; // JSON array of enabled features
    
    @Column(name = "settings", columnDefinition = "jsonb")
    private String settings; // JSON object of settings
    
    @Column(name = "branding", columnDefinition = "jsonb")
    private String branding; // JSON object for UI customization
    
    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt = LocalDateTime.now();
    
    // Getters and setters...
}
```

## Admin Panel

### Tenant Admin Controller

```java
@RestController
@RequestMapping("/api/admin/tenants")
@PreAuthorize("hasRole('SUPER_ADMIN')")
public class TenantAdminController {
    
    private final TenantService tenantService;
    private final TenantUserService tenantUserService;
    
    @PostMapping
    public ResponseEntity<TenantDTO> createTenant(
            @RequestBody @Validated CreateTenantRequestDTO request) {
        
        Tenant tenant = tenantService.createTenant(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(TenantDTOMapper.toDTO(tenant));
    }
    
    @GetMapping
    public ResponseEntity<Page<TenantDTO>> getAllTenants(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) TenantStatus status) {
        
        Pageable pageable = PageRequest.of(page, size);
        Page<Tenant> tenants = tenantService.getAllTenants(pageable, status);
        Page<TenantDTO> tenantDTOs = tenants.map(TenantDTOMapper::toDTO);
        
        return ResponseEntity.ok(tenantDTOs);
    }
    
    @GetMapping("/{tenantId}")
    public ResponseEntity<TenantDetailsDTO> getTenantDetails(@PathVariable String tenantId) {
        Tenant tenant = tenantService.getTenantById(tenantId);
        TenantConfig config = tenantService.getTenantConfig(tenantId);
        
        TenantDetailsDTO details = new TenantDetailsDTO();
        details.setTenant(TenantDTOMapper.toDTO(tenant));
        details.setConfig(TenantConfigDTOMapper.toDTO(config));
        details.setUserCount(tenantUserService.getUserCount(tenantId));
        details.setActiveUserCount(tenantUserService.getActiveUserCount(tenantId));
        
        return ResponseEntity.ok(details);
    }
    
    @PutMapping("/{tenantId}/status")
    public ResponseEntity<TenantDTO> updateTenantStatus(
            @PathVariable String tenantId,
            @RequestBody @Validated UpdateTenantStatusRequestDTO request) {
        
        Tenant tenant = tenantService.updateTenantStatus(tenantId, request.getStatus());
        return ResponseEntity.ok(TenantDTOMapper.toDTO(tenant));
    }
    
    @PutMapping("/{tenantId}/config")
    public ResponseEntity<TenantConfigDTO> updateTenantConfig(
            @PathVariable String tenantId,
            @RequestBody @Validated TenantConfigUpdateDTO request) {
        
        TenantConfig config = tenantService.updateTenantConfig(tenantId, request);
        return ResponseEntity.ok(TenantConfigDTOMapper.toDTO(config));
    }
    
    @GetMapping("/{tenantId}/users")
    public ResponseEntity<Page<TenantUserDTO>> getTenantUsers(
            @PathVariable String tenantId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        
        // Temporarily set tenant context for admin operations
        TenantContext.setCurrentTenant(tenantId);
        try {
            Pageable pageable = PageRequest.of(page, size);
            Page<TenantUser> users = tenantUserService.getTenantUsers(pageable);
            Page<TenantUserDTO> userDTOs = users.map(TenantUserDTOMapper::toDTO);
            
            return ResponseEntity.ok(userDTOs);
        } finally {
            TenantContext.clear();
        }
    }
}
```

### Tenant User Management Controller

```java
@RestController
@RequestMapping("/api/tenant/users")
@PreAuthorize("hasRole('TENANT_ADMIN')")
public class TenantUserController {
    
    private final TenantAwareUserService userService;
    
    @GetMapping
    public ResponseEntity<Page<TenantUserDTO>> getTenantUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String search) {
        
        Pageable pageable = PageRequest.of(page, size);
        Page<TenantUser> users = userService.searchTenantUsers(search, pageable);
        Page<TenantUserDTO> userDTOs = users.map(TenantUserDTOMapper::toDTO);
        
        return ResponseEntity.ok(userDTOs);
    }
    
    @PostMapping
    public ResponseEntity<TenantUserDTO> createTenantUser(
            @RequestBody @Validated CreateTenantUserRequestDTO request) {
        
        TenantUser user = userService.createTenantUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(TenantUserDTOMapper.toDTO(user));
    }
    
    @PutMapping("/{userId}/role")
    public ResponseEntity<TenantUserDTO> updateUserRole(
            @PathVariable Long userId,
            @RequestBody @Validated UpdateUserRoleRequestDTO request) {
        
        TenantUser user = userService.updateTenantRole(userId, request.getRole());
        return ResponseEntity.ok(TenantUserDTOMapper.toDTO(user));
    }
    
    @DeleteMapping("/{userId}")
    public ResponseEntity<Void> deleteTenantUser(@PathVariable Long userId) {
        userService.deleteTenantUser(userId);
        return ResponseEntity.noContent().build();
    }
}
```

## Token Revocation (Admin Only)

A new admin-only endpoint allows you to revoke any access or refresh token:

```http
POST /api/auth/revoke
Authorization: Bearer <admin-access-token>
Content-Type: application/json

"<token-to-revoke>"
```

- Works for both access and refresh tokens.
- Revoked tokens are blocked in memory or Redis (depending on config).

## Cookie-based Authentication

- All authentication now uses cookies for access and refresh tokens.
- Cookies are set with `httpOnly`, `secure`, and `sameSite` flags for security.
- Most endpoints do not accept Authorization headers anymore (except /revoke).
- For SaaS frontends, ensure your HTTP client supports cookies.

## Rate Limiting and Blocklist

- Rate limiting is enabled by default (in-memory for dev, Redis for prod).
- Token blocklist is enabled by default (in-memory for dev, Redis for prod).
- Configure with `ricardo.auth.rate-limiter` and `ricardo.auth.token-blocklist`.

## Testing

### Multi-Tenant Integration Test

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
public class MultiTenantIntegrationTest {
    
    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15")
            .withDatabaseName("multitenant_test")
            .withUsername("test")
            .withPassword("test");
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Autowired
    private TenantService tenantService;
    
    @Test
    public void testTenantIsolation() {
        // Create two tenants
        CreateTenantRequestDTO tenant1Request = new CreateTenantRequestDTO();
        tenant1Request.setTenantId("tenant1");
        tenant1Request.setName("Tenant 1");
        tenant1Request.setDatabaseStrategy(DatabaseStrategy.SCHEMA_PER_TENANT);
        
        CreateTenantRequestDTO tenant2Request = new CreateTenantRequestDTO();
        tenant2Request.setTenantId("tenant2");
        tenant2Request.setName("Tenant 2");
        tenant2Request.setDatabaseStrategy(DatabaseStrategy.SCHEMA_PER_TENANT);
        
        Tenant tenant1 = tenantService.createTenant(tenant1Request);
        Tenant tenant2 = tenantService.createTenant(tenant2Request);
        
        // Create users in each tenant
        CreateUserRequestDTO user1Request = new CreateUserRequestDTO();
        user1Request.setUsername("user1");
        user1Request.setEmail("user1@tenant1.com");
        user1Request.setPassword("SecurePass@123!");
        
        CreateUserRequestDTO user2Request = new CreateUserRequestDTO();
        user2Request.setUsername("user1"); // Same username, different tenant
        user2Request.setEmail("user1@tenant2.com");
        user2Request.setPassword("SecurePass@123!");
        
        // Create user in tenant1
        HttpHeaders headers1 = new HttpHeaders();
        headers1.set("X-Tenant-ID", "tenant1");
        HttpEntity<CreateUserRequestDTO> entity1 = new HttpEntity<>(user1Request, headers1);
        
        ResponseEntity<UserDTO> response1 = restTemplate.postForEntity(
            "/api/users/create", entity1, UserDTO.class);
        
        assertThat(response1.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        
        // Create user in tenant2
        HttpHeaders headers2 = new HttpHeaders();
        headers2.set("X-Tenant-ID", "tenant2");
        HttpEntity<CreateUserRequestDTO> entity2 = new HttpEntity<>(user2Request, headers2);
        
        ResponseEntity<UserDTO> response2 = restTemplate.postForEntity(
            "/api/users/create", entity2, UserDTO.class);
        
        assertThat(response2.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        
        // Verify tenant isolation - login with tenant1 credentials using tenant2 header should fail
        LoginRequestDTO loginRequest = new LoginRequestDTO();
        loginRequest.setEmail("user1@tenant1.com");
        loginRequest.setPassword("SecurePass@123!");
        
        HttpEntity<LoginRequestDTO> loginEntity = new HttpEntity<>(loginRequest, headers2);
        ResponseEntity<TokenDTO> loginResponse = restTemplate.postForEntity(
            "/api/auth/login", loginEntity, TokenDTO.class);
        
        assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
    
    @Test
    public void testTenantConfigurationIsolation() {
        // Test that tenant configurations don't leak between tenants
        String tenant1Id = "config-test-1";
        String tenant2Id = "config-test-2";
        
        // Create tenants with different configurations
        CreateTenantRequestDTO request1 = createTenantRequest(tenant1Id, "Config Test 1");
        CreateTenantRequestDTO request2 = createTenantRequest(tenant2Id, "Config Test 2");
        
        tenantService.createTenant(request1);
        tenantService.createTenant(request2);
        
        // Update config for tenant1
        TenantConfigUpdateDTO config1 = new TenantConfigUpdateDTO();
        config1.setMaxUsers(10);
        config1.setFeatures(Arrays.asList("FEATURE_A", "FEATURE_B"));
        
        tenantService.updateTenantConfig(tenant1Id, config1);
        
        // Update config for tenant2
        TenantConfigUpdateDTO config2 = new TenantConfigUpdateDTO();
        config2.setMaxUsers(20);
        config2.setFeatures(Arrays.asList("FEATURE_C", "FEATURE_D"));
        
        tenantService.updateTenantConfig(tenant2Id, config2);
        
        // Verify configurations are isolated
        TenantConfig retrievedConfig1 = tenantService.getTenantConfig(tenant1Id);
        TenantConfig retrievedConfig2 = tenantService.getTenantConfig(tenant2Id);
        
        assertThat(retrievedConfig1.getMaxUsers()).isEqualTo(10);
        assertThat(retrievedConfig2.getMaxUsers()).isEqualTo(20);
        
        assertThat(retrievedConfig1.getFeatures()).contains("FEATURE_A", "FEATURE_B");
        assertThat(retrievedConfig2.getFeatures()).contains("FEATURE_C", "FEATURE_D");
    }
}
```

This multi-tenant example demonstrates how to build a comprehensive SaaS platform with Ricardo Auth, featuring complete
tenant isolation, flexible tenant resolution strategies, and robust admin functionality for managing multiple tenants
and their users.
