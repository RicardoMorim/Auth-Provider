# Database Configuration

> **Breaking Change (v2.0.0):**
> - Authentication now uses secure cookies (`access_token`, `refresh_token`) with `HttpOnly`, `Secure`, and `SameSite` flags by default. You must use HTTPS in production or set `ricardo.auth.cookies.access.secure: false` for local development only.
> - New blocklist and rate limiting features are available (see below).
> - New `/api/auth/revoke` admin endpoint for revoking tokens (access or refresh).

Configure **Ricardo Auth with various databases** for development, testing, and production environments.

## 📋 Quick Navigation

- [Database Support](#database-support)
- [H2 (Development)](#h2-development)
- [PostgreSQL (Recommended)](#postgresql-recommended)
- [MySQL](#mysql)
- [SQL Server](#sql-server)
- [Connection Pooling](#connection-pooling)
- [Schema Management](#schema-management)
- [Troubleshooting](#troubleshooting)

## Database Support

Ricardo Auth supports all databases compatible with Spring Boot JPA:

| Database | Status | Best For | Configuration Complexity |
|----------|--------|----------|--------------------------|
| **H2** | ✅ Supported | Development, Testing | ⭐ Easy |
| **PostgreSQL** | ✅ Recommended | Production, Development | ⭐⭐ Medium |
| **MySQL** | ✅ Supported | Production, Legacy systems | ⭐⭐ Medium |
| **SQL Server** | ✅ Supported | Enterprise, Windows environments | ⭐⭐⭐ Advanced |
| **Oracle** | ✅ Supported | Enterprise | ⭐⭐⭐ Advanced |
| **SQLite** | ✅ Supported | Embedded, Testing | ⭐ Easy |

## H2 (Development)

Perfect for **development and testing** - no external database required.

### In-Memory Database (Temporary)
```yaml
# application-dev.yml
spring:
  datasource:
    url: jdbc:h2:mem:authdb
    driver-class-name: org.h2.Driver
    username: sa
    password: password

# Ricardo Auth Configuration
ricardo:
  auth:
    jwt:
      secret: "dev-secret-key"
      access-token-expiration: 86400000
      refresh-token-expiration: 604800000
    # --- NEW: Blocklist and Rate Limiter ---
    token-blocklist:
      enabled: true
      type: memory   # or 'redis' for distributed blocklist
    rate-limiter:
      enabled: true
      type: memory   # or 'redis' for distributed rate limiting
      max-requests: 100
      time-window-ms: 60000
    # --- NEW: Cookie Security ---
    cookies:
      access:
        secure: true
        http-only: true
        same-site: Strict
        path: /
      refresh:
        secure: true
        http-only: true
        same-site: Strict
        path: /api/auth/refresh
  redirect-https: true
```

### File-Based Database (Persistent)
```yaml
# application-dev.yml
spring:
  datasource:
    url: jdbc:h2:file:./data/authdb  # Saves to ./data/authdb.mv.db
    driver-class-name: org.h2.Driver
    username: sa
    password: password
  
  jpa:
    hibernate:
      ddl-auto: update       # Update schema, keep data
    show-sql: true
```

### Dependencies
```xml
<dependency>
    <groupId>com.h2database</groupId>
    <artifactId>h2</artifactId>
    <scope>runtime</scope>
</dependency>
```

### H2 Console Access
1. Start your application
2. Visit: http://localhost:8080/h2-console
3. Use connection details:
   - **JDBC URL:** `jdbc:h2:mem:authdb` (or your configured URL)
   - **Username:** `sa`
   - **Password:** `password`

## PostgreSQL (Recommended)

**Best choice for production** - excellent performance, reliability, and features.

### Basic Configuration
```yaml
# application-prod.yml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/auth_db
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
    driver-class-name: org.postgresql.Driver
  
  jpa:
    hibernate:
      ddl-auto: validate     # Validate schema only
    show-sql: false
    database-platform: org.hibernate.dialect.PostgreSQLDialect
    properties:
      hibernate:
        format_sql: false
        jdbc:
          lob:
            non_contextual_creation: true
```

### With Connection Pooling (HikariCP)
```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/auth_db
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
    driver-class-name: org.postgresql.Driver
    hikari:
      maximum-pool-size: 20
      minimum-idle: 5
      connection-timeout: 30000
      idle-timeout: 600000
      max-lifetime: 1800000
      leak-detection-threshold: 60000
```

### Dependencies
```xml
<dependency>
    <groupId>org.postgresql</groupId>
    <artifactId>postgresql</artifactId>
    <scope>runtime</scope>
</dependency>
```

### Docker Setup
```yaml
# docker-compose.yml
version: '3.8'
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: auth_db
      POSTGRES_USER: auth_user
      POSTGRES_PASSWORD: secure_password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql

volumes:
  postgres_data:
```

### Manual Database Setup
```sql
-- Create database
CREATE DATABASE auth_db;

-- Create user
CREATE USER auth_user WITH PASSWORD 'secure_password';

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE auth_db TO auth_user;

-- Connect to database
\c auth_db

-- Grant schema permissions
GRANT ALL ON SCHEMA public TO auth_user;
```

## MySQL

Popular choice for **web applications** and existing MySQL infrastructure.

### Basic Configuration
```yaml
# application.yml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/auth_db?useSSL=false&serverTimezone=UTC&allowPublicKeyRetrieval=true
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
    driver-class-name: com.mysql.cj.jdbc.Driver
  
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false
    database-platform: org.hibernate.dialect.MySQLDialect
    properties:
      hibernate:
        format_sql: false
```

### With Connection Pooling
```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/auth_db?useSSL=false&serverTimezone=UTC
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
    driver-class-name: com.mysql.cj.jdbc.Driver
    hikari:
      maximum-pool-size: 20
      minimum-idle: 5
      connection-timeout: 30000
      idle-timeout: 600000
      max-lifetime: 1800000
```

### Dependencies
```xml
<dependency>
    <groupId>com.mysql</groupId>
    <artifactId>mysql-connector-j</artifactId>
    <scope>runtime</scope>
</dependency>
```

### Docker Setup
```yaml
# docker-compose.yml
version: '3.8'
services:
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_DATABASE: auth_db
      MYSQL_USER: auth_user
      MYSQL_PASSWORD: secure_password
      MYSQL_ROOT_PASSWORD: root_password
    ports:
      - "3306:3306"
    volumes:
      - mysql_data:/var/lib/mysql

volumes:
  mysql_data:
```

### Manual Database Setup
```sql
-- Create database
CREATE DATABASE auth_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user
CREATE USER 'auth_user'@'%' IDENTIFIED BY 'secure_password';

-- Grant permissions
GRANT ALL PRIVILEGES ON auth_db.* TO 'auth_user'@'%';
FLUSH PRIVILEGES;
```

## SQL Server

Enterprise choice for **Windows environments** and Microsoft ecosystems.

### Basic Configuration
```yaml
# application.yml
spring:
  datasource:
    url: jdbc:sqlserver://localhost:1433;databaseName=auth_db;encrypt=true;trustServerCertificate=true
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
    driver-class-name: com.microsoft.sqlserver.jdbc.SQLServerDriver
  
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false
    database-platform: org.hibernate.dialect.SQLServerDialect
```

### Dependencies
```xml
<dependency>
    <groupId>com.microsoft.sqlserver</groupId>
    <artifactId>mssql-jdbc</artifactId>
    <scope>runtime</scope>
</dependency>
```

### Docker Setup
```yaml
# docker-compose.yml
version: '3.8'
services:
  sqlserver:
    image: mcr.microsoft.com/mssql/server:2022-latest
    environment:
      SA_PASSWORD: YourStrong@Passw0rd
      ACCEPT_EULA: Y
    ports:
      - "1433:1433"
    volumes:
      - sqlserver_data:/var/opt/mssql

volumes:
  sqlserver_data:
```

## Connection Pooling

### HikariCP (Default and Recommended)
```yaml
spring:
  datasource:
    hikari:
      # Pool sizing
      maximum-pool-size: 20          # Maximum connections
      minimum-idle: 5                # Minimum idle connections
      
      # Timeouts
      connection-timeout: 30000      # 30 seconds
      idle-timeout: 600000           # 10 minutes
      max-lifetime: 1800000          # 30 minutes
      
      # Monitoring
      leak-detection-threshold: 60000 # 60 seconds
      
      # Connection validation
      validation-timeout: 5000       # 5 seconds
      
      # Pool name for monitoring
      pool-name: AuthHikariPool
```

### Connection Pool Monitoring
```yaml
# Enable metrics
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
  metrics:
    enable:
      hikaricp: true

# Custom health indicators
management:
  health:
    db:
      enabled: true
    diskspace:
      enabled: true
```

### Pool Size Guidelines

| Application Type | Max Pool Size | Min Idle |
|-----------------|---------------|----------|
| Small web app | 10-15 | 2-5 |
| Medium web app | 15-25 | 5-10 |
| Large web app | 25-50 | 10-15 |
| Microservice | 5-15 | 2-5 |
| High-traffic API | 30-100 | 15-25 |

## Schema Management

### Development (Auto-create)
```yaml
spring:
  jpa:
    hibernate:
      ddl-auto: create-drop    # Recreate on restart
      # ddl-auto: create       # Create once
      # ddl-auto: update       # Update existing schema
```

### Production (Manual control)
```yaml
spring:
  jpa:
    hibernate:
      ddl-auto: validate       # Only validate, no changes
```

### Using Flyway (Recommended for Production)
```xml
<dependency>
    <groupId>org.flywaydb</groupId>
    <artifactId>flyway-core</artifactId>
</dependency>
```

```yaml
spring:
  flyway:
    enabled: true
    locations: classpath:db/migration
    baseline-on-migrate: true
```

**Migration files in `src/main/resources/db/migration/`:**
```sql
-- V1__Create_users_table.sql
CREATE TABLE users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- V2__Create_user_roles_table.sql
CREATE TABLE user_roles (
    user_id BIGINT,
    role VARCHAR(50),
    PRIMARY KEY (user_id, role),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Using Liquibase
```xml
<dependency>
    <groupId>org.liquibase</groupId>
    <artifactId>liquibase-core</artifactId>
</dependency>
```

```yaml
spring:
  liquibase:
    change-log: classpath:db/changelog/db.changelog-master.xml
```

## Database Schema

Ricardo Auth creates these tables automatically:

### Users Table
```sql
CREATE TABLE users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### User Roles Table
```sql
CREATE TABLE user_roles (
    user_id BIGINT NOT NULL,
    role VARCHAR(50) NOT NULL,
    PRIMARY KEY (user_id, role),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### Indexes (Automatically created)
```sql
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
```

## Environment-Specific Configuration

### Development
```yaml
# application-dev.yml
spring:
  datasource:
    url: jdbc:h2:file:./dev-data/authdb
    username: sa
    password: password
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true
```

### Testing
```yaml
# application-test.yml
spring:
  datasource:
    url: jdbc:h2:mem:testdb
    username: sa
    password: password
  jpa:
    hibernate:
      ddl-auto: create-drop
    show-sql: false
```

### Production
```yaml
# application-prod.yml
spring:
  datasource:
    url: ${DATABASE_URL}
    username: ${DATABASE_USERNAME}
    password: ${DATABASE_PASSWORD}
    hikari:
      maximum-pool-size: 20
      minimum-idle: 5
      leak-detection-threshold: 60000
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false
```

## Troubleshooting

### Common Database Issues

**1. Connection Refused**
```
Error: Connection refused to database
```
**Solutions:**
- Check database is running
- Verify connection URL, username, password
- Check firewall settings
- Ensure database accepts connections from your IP

**2. Schema/Table Not Found**
```
Error: Table 'users' doesn't exist
```
**Solutions:**
- Set `ddl-auto: create` or `ddl-auto: update`
- Run database migrations manually
- Check database name is correct

**3. Pool Exhaustion**
```
Error: Connection is not available, request timed out
```
**Solutions:**
- Increase `maximum-pool-size`
- Check for connection leaks
- Optimize query performance
- Monitor connection usage

**4. Authentication Failed**
```
Error: Access denied for user
```
**Solutions:**
- Verify database credentials
- Check user has necessary permissions
- Ensure user can connect from application host

### Connection Testing

**Test connection without starting full application:**
```java
@Test
public void testDatabaseConnection() {
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl("jdbc:postgresql://localhost:5432/auth_db");
    config.setUsername("auth_user");
    config.setPassword("password");
    
    try (HikariDataSource dataSource = new HikariDataSource(config);
         Connection connection = dataSource.getConnection()) {
        
        assertTrue(connection.isValid(5));
        System.out.println("Database connection successful!");
    } catch (SQLException e) {
        fail("Database connection failed: " + e.getMessage());
    }
}
```

### Health Checks
```bash
# Check database connectivity
curl http://localhost:8080/actuator/health

# Detailed health info (if security allows)
curl http://localhost:8080/actuator/health/db
```

### Performance Monitoring
```yaml
# Enable detailed metrics
management:
  endpoints:
    web:
      exposure:
        include: metrics,health,info
  metrics:
    enable:
      hikaricp: true
      jdbc: true
```

**View metrics:**
```bash
# Connection pool metrics
curl http://localhost:8080/actuator/metrics/hikaricp.connections.active

# Database query metrics  
curl http://localhost:8080/actuator/metrics/jdbc.connections.active
```

## Migration from Other Databases

### From H2 to PostgreSQL
1. Export H2 data: `SCRIPT TO 'backup.sql'`
2. Convert SQL syntax for PostgreSQL
3. Update configuration to PostgreSQL
4. Import data to PostgreSQL

### From MySQL to PostgreSQL
1. Use migration tools like `pgloader`
2. Update configuration
3. Test thoroughly

**Example pgloader config:**
```
load database
    from mysql://user:pass@localhost/auth_db
    into postgresql://user:pass@localhost/auth_db
alter schema 'auth_db' rename to 'public';
```

This comprehensive database configuration guide covers all major database systems and deployment scenarios for Ricardo Auth.
