# Startup Issues

Fix **application startup problems** with Ricardo Auth quickly and efficiently.

---

> **Breaking Changes (v3.0.0):**
> - **UUID Primary Keys:** All user IDs are now UUID instead of Long
> - **Enhanced Decoupling:** New factory pattern for user creation
> - **Repository Types:** Choose between JPA and PostgreSQL implementations

## 📋 Quick Navigation

- [Common Startup Errors](#common-startup-errors)
- [Configuration Issues](#configuration-issues)
- [Dependency Problems](#dependency-problems)
- [Database Issues](#database-issues)
- [JVM and Memory Issues](#jvm-and-memory-issues)
- [IDE-Specific Issues](#ide-specific-issues)
- [Quick Fixes](#quick-fixes)

## Common Startup Errors

> **Novidade v2.0.0:**
> - Cookies de autenticação agora usam flags de segurança (`HttpOnly`, `Secure`, `SameSite`) por padrão. HTTPS é
    obrigatório para produção.
> - Blocklist e rate limiting (memória/Redis) são ativados por padrão para maior proteção.
> - Endpoint de revogação de token disponível em `/api/auth/revoke` (ADMIN).

### JWT Secret Not Configured

**❌ Error:**

```
***************************
APPLICATION FAILED TO START
***************************

Description:
Property 'ricardo.auth.jwt.secret' is required but not configured.

Action:
Configure the JWT secret in your application.yml or set the RICARDO_AUTH_JWT_SECRET environment variable.
```

**✅ Solution:**

```yaml
# application.yml
ricardo:
  auth:
    jwt:
      secret: "your-256-bit-secret-key-here-make-it-long-and-secure"
```

**Or use environment variable:**

```bash
export RICARDO_AUTH_JWT_SECRET="your-256-bit-secret-key-here"
```

**❗ Importante:** O segredo JWT deve ser longo, aleatório e nunca exposto publicamente. Use variáveis de ambiente em
produção.

### Missing JPA Dependencies

**❌ Error:**

```
***************************
APPLICATION FAILED TO START
***************************

Description:
Failed to configure a DataSource: 'url' attribute is not specified and no embedded datasource could be configured.

Action:
Consider the following:
    If you want an embedded database (H2, HSQL or Derby), please put it on the classpath.
    If you have database settings to be loaded from a particular profile you may need to activate it.
```

**✅ Solution - Add Dependencies:**

```xml
<dependencies>
    <!-- Spring Boot JPA (Required) -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    
    <!-- Database Driver (Choose one) -->
    <!-- H2 for development -->
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <scope>runtime</scope>
    </dependency>
    
    <!-- OR PostgreSQL for production -->
    <dependency>
        <groupId>org.postgresql</groupId>
        <artifactId>postgresql</artifactId>
        <scope>runtime</scope>
    </dependency>
</dependencies>
```

**✅ Solution - Add Database Configuration:**

```yaml
# For H2 (Development)
spring:
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
    username: sa
    password: password

# For PostgreSQL (Production)
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/myapp
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
```

**Nota:** Para usar blocklist ou rate limiting com Redis, adicione as dependências do Spring Data Redis.

### Bean Creation Errors

**❌ Error:**

```
Error creating bean with name 'authAutoConfiguration': 
Injection of autowired dependencies failed; nested exception is 
java.lang.NoSuchMethodError: 'org.springframework.security.config.annotation.web.builders.HttpSecurity'
```

**✅ Solution - Check Spring Boot Version:**

```xml
<!-- Ensure compatible Spring Boot version -->
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.0</version>  <!-- Use 3.2.0 or later -->
    <relativePath/>
</parent>
```

**✅ Solution - Check Java Version:**

```xml
<properties>
    <java.version>21</java.version>  <!-- Use Java 21 or later -->
</properties>
```

### Port Already in Use

**❌ Error:**

```
Web server failed to start. Port 8080 was already in use.

Action:
Identify and stop the process that's listening on port 8080 or configure this application to listen on another port.
```

**✅ Solutions:**

**1. Use Different Port:**

```yaml
# application.yml
server:
  port: 8081  # Or any available port
```

**2. Find and Kill Process:**

```bash
# Find process using port 8080
netstat -tlnp | grep :8080
# or
lsof -i :8080

# Kill the process (replace PID)
kill -9 <PID>
```

**3. Use Random Port:**

```yaml
# application.yml
server:
  port: 0  # Spring will choose random available port
```

**Dica:** Se usar HTTPS, certifique-se de que a porta 443 ou 8443 está livre.

## Configuration Issues

### Invalid YAML Syntax

**❌ Error:**

```
Caused by: org.yaml.snakeyaml.scanner.ScannerException: 
mapping values are not allowed here
```

**✅ Solution - Check YAML Indentation:**

```yaml
# ❌ Wrong (missing spaces)
ricardo:
auth:
  jwt:
    secret: "key"

# ✅ Correct (proper indentation)
ricardo:
  auth:
    jwt:
      secret: "key"
```

### Profile-Specific Issues

**❌ Error:**

```
The following profiles are active: prod
But production database configuration is missing
```

**✅ Solution - Set Active Profile:**

```yaml
# application.yml
spring:
  profiles:
    active: dev  # Use dev profile by default

---
# Development configuration
spring:
  config:
    activate:
      on-profile: dev
  datasource:
    url: jdbc:h2:mem:devdb

---
# Production configuration  
spring:
  config:
    activate:
      on-profile: prod
  datasource:
    url: ${DATABASE_URL}
```

### Property Binding Errors

**❌ Error:**

```
Binding to target failed:
Property: ricardo.auth.jwt.expiration
Value: "invalid"
Reason: Failed to convert property value of type 'java.lang.String' to required type 'long'
```

**✅ Solution - Use Correct Data Types:**

```yaml
# ❌ Wrong (string value)
ricardo:
  auth:
    jwt:
      expiration: "24 hours"

# ✅ Correct (numeric value in milliseconds)
ricardo:
  auth:
    jwt:
      expiration: 86400000  # 24 hours
```

## Dependency Problems

### Version Conflicts

**❌ Error:**

```
java.lang.NoSuchMethodError: 'org.springframework.security.config.annotation.web.builders.HttpSecurity.authorizeHttpRequests()'
```

**✅ Solution - Check Dependency Versions:**

```bash
# Check dependency tree
mvn dependency:tree

# Look for version conflicts
mvn dependency:tree | grep -E "(spring-security|spring-boot)"
```

**✅ Solution - Use BOM for Version Management:**

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-dependencies</artifactId>
            <version>3.2.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

### Missing Required Dependencies

**❌ Error:**

```
java.lang.ClassNotFoundException: org.springframework.security.web.SecurityFilterChain
```

**✅ Solution - Add Missing Dependencies:**

```xml
<!-- Often missing dependencies -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
```

### Conflicting Auto-Configuration

**❌ Error:**

```
Field authConfiguration in com.ricardo.auth.config.AuthAutoConfiguration required a bean of type 'javax.sql.DataSource' that could not be found.
```

**✅ Solution - Exclude Conflicting Auto-Configuration:**

```java
@SpringBootApplication(exclude = {
    DataSourceAutoConfiguration.class  // If you want to configure DataSource manually
})
public class MyApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}
```

## Database Issues

### Database Connection Failed

**❌ Error:**

```
java.sql.SQLException: Connection refused. Check that the hostname and port are correct and that the postmaster is accepting TCP/IP connections.
```

**✅ Solutions:**

**1. Check Database is Running:**

```bash
# PostgreSQL
sudo systemctl status postgresql
# or
brew services list | grep postgresql

# MySQL  
sudo systemctl status mysql
# or
brew services list | grep mysql
```

**2. Check Connection Details:**

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/myapp  # Check host, port, database name
    username: ${DB_USERNAME}  # Check username
    password: ${DB_PASSWORD}  # Check password
```

**3. Test Connection Manually:**

```bash
# PostgreSQL
psql -h localhost -p 5432 -U myuser -d myapp

# MySQL
mysql -h localhost -P 3306 -u myuser -p myapp
```

### Schema/Table Creation Issues

**❌ Error:**

```
Caused by: org.hibernate.tool.schema.spi.SchemaManagementException: Unable to execute schema management to JDBC target
```

**✅ Solution - Check DDL Mode:**

```yaml
spring:
  jpa:
    hibernate:
      ddl-auto: create-drop  # For development
      # ddl-auto: update     # For development with data persistence
      # ddl-auto: validate   # For production
```

**✅ Solution - Check Database Permissions:**

```sql
-- Grant necessary permissions
GRANT CREATE, ALTER, DROP, INSERT, UPDATE, DELETE, SELECT ON myapp.* TO 'myuser'@'%';
```

## JVM and Memory Issues

### Out of Memory Errors

**❌ Error:**

```
java.lang.OutOfMemoryError: Java heap space
```

**✅ Solution - Increase Heap Size:**

```bash
# Set JVM options
export JAVA_OPTS="-Xms512m -Xmx2048m"

# Or in application startup
java -Xms512m -Xmx2048m -jar myapp.jar
```

### Java Version Issues

**❌ Error:**

```
java.lang.UnsupportedClassVersionError: com/ricardo/auth/AuthAutoConfiguration has been compiled by a more recent version of the Java Runtime
```

**✅ Solution - Use Compatible Java Version:**

```bash
# Check current Java version
java -version

# Ricardo Auth requires Java 21+
# Install Java 21 if needed
sdk install java 21.0.1-tem
sdk use java 21.0.1-tem
```

### Classpath Issues

**❌ Error:**

```
java.lang.NoClassDefFoundError: Could not initialize class com.ricardo.auth.AuthAutoConfiguration
```

**✅ Solutions:**

**1. Clean and Rebuild:**

```bash
mvn clean compile
mvn clean install
```

**2. Check Classpath:**

```bash
# Verify JAR is in classpath
mvn dependency:tree | grep auth-spring-boot-starter
```

**3. IDE Cache Issues:**

```bash
# IntelliJ IDEA
File → Invalidate Caches and Restart

# Eclipse
Project → Clean → Clean all projects
```

## IDE-Specific Issues

### IntelliJ IDEA Issues

**❌ Problem:** Configuration not recognized
**✅ Solution:**

1. `File → Reload Gradle/Maven Project`
2. `Build → Rebuild Project`
3. `File → Invalidate Caches and Restart`

**❌ Problem:** Auto-completion not working
**✅ Solution:**

1. `File → Project Structure → Modules`
2. Ensure `src/main/java` is marked as Sources
3. Ensure `src/main/resources` is marked as Resources

### Eclipse Issues

**❌ Problem:** Build path errors
**✅ Solution:**

1. `Project → Properties → Java Build Path`
2. `Libraries → Add Library → User Library`
3. Add required JARs manually if needed

### VS Code Issues

**❌ Problem:** Java extension not recognizing project
**✅ Solution:**

1. Install "Extension Pack for Java"
2. `Ctrl+Shift+P → Java: Reload Projects`
3. Ensure `pom.xml` or `build.gradle` is in workspace root

## Quick Fixes

### Emergency Quick Start

**If nothing works, try this minimal setup:**

```xml
<!-- pom.xml - Minimal dependencies -->
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.0</version>
</parent>

<dependencies>
    <dependency>
        <groupId>io.github.ricardomorim</groupId>
        <artifactId>auth-spring-boot-starter</artifactId>
        <version>1.1.0</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
    </dependency>
</dependencies>
```

```yaml
# application.yml - Minimal configuration
ricardo:
  auth:
    jwt:
      secret: "this-is-a-very-long-secret-key-for-jwt-token-signing-must-be-256-bits"

spring:
  datasource:
    url: jdbc:h2:mem:testdb
    username: sa
    password: password
  jpa:
    hibernate:
      ddl-auto: create-drop
```

```java
// Application.java - Minimal main class
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

### Common Command-Line Fixes

```bash
# 1. Clean everything
mvn clean
rm -rf target/
rm -rf ~/.m2/repository/io/github/ricardomorim/

# 2. Force dependency update
mvn dependency:purge-local-repository
mvn clean install

# 3. Check for port conflicts
netstat -tlnp | grep :8080
lsof -i :8080

# 4. Verify Java version
java -version
javac -version

# 5. Check environment variables
env | grep RICARDO
env | grep SPRING
```

### Startup Verification Checklist

- [ ] **Java 21+** installed and active
- [ ] **Spring Boot 3.2+** in pom.xml
- [ ] **JPA dependency** present
- [ ] **Database dependency** (H2, PostgreSQL, etc.) present
- [ ] **JWT secret** configured (256+ bits)
- [ ] **Database configuration** present
- [ ] **Port 8080** available or alternative configured
- [ ] **No YAML syntax errors**
- [ ] **Dependencies** downloaded (`~/.m2/repository`)
- [ ] **IDE caches** cleared

### Debug Mode Startup

**Dica extra:**

- Para depurar problemas de cookies, use ferramentas como DevTools do navegador e verifique as flags `Secure`,
  `HttpOnly` e `SameSite`.
- Se o login não funcionar em produção, verifique se HTTPS está ativo e se o navegador não está bloqueando cookies
  inseguros.

```yaml
logging:
  level:
    root: INFO
    com.ricardo.auth: DEBUG
    org.springframework.boot.autoconfigure: DEBUG
    org.springframework.security: DEBUG
```

```bash
# Start with debug output
java -jar myapp.jar --debug

# Or with Maven
mvn spring-boot:run -Dspring-boot.run.arguments="--debug"
```

### Get Help

> **Mudança importante:**
> - Se você atualizou da v1.x.x, revise as configurações de cookies, HTTPS e blocklist. Veja
    o [Guia de Segurança](../security-guide.md) para detalhes.

If these solutions don't work:

1. **Enable debug logging** (see above)
2. **Check the complete error stack trace**
3. **Verify system requirements** (Java 21+, Spring Boot 3.2+)
4. **Create a minimal reproduction** project
5. **Search existing issues** on GitHub
6. **Create a new issue** with full error details

Most startup issues are configuration-related and can be solved by following this guide systematically.
