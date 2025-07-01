# Configuration Overview

Complete guide to configuring Ricardo Auth for your specific needs.

## 🚀 Quick Setup (2 minutes)

**Minimum required configuration to get started:**

```yaml
ricardo:
  auth:
    jwt:
      secret: "your-256-bit-secret-key-here-make-it-long-and-secure"
```

That's it! Ricardo Auth will use sensible defaults for everything else.

## 📋 Configuration Checklist

### ✅ **Required (Must Have)**
- [ ] [JWT secret key configured](basic.md#jwt-configuration) - `ricardo.auth.jwt.secret`
- [ ] [Database dependency added](basic.md#database-setup) - `spring-boot-starter-data-jpa`
- [ ] [Database configured](database.md) - Connection details in `application.yml`

### 🎯 **Recommended for Production**
- [ ] [Environment variables for secrets](environment.md) - Don't hardcode secrets
- [ ] [Password policy configured](password-policy.md) - Strengthen password requirements
- [ ] [Database connection pooling](database.md#connection-pooling) - Performance optimization
- [ ] [Security configuration](security.md) - HTTPS, CORS, headers
- [ ] [Logging levels](basic.md#logging-configuration) - Appropriate for environment

### ⚙️ **Optional Customizations**
- [ ] [Custom token expiration](basic.md#jwt-configuration) - Adjust for your use case
- [ ] [Disabled endpoints](basic.md#endpoint-configuration) - Turn off unused features
- [ ] [Custom security rules](security.md#custom-security) - Advanced security needs
- [ ] [Advanced features](advanced.md) - Rate limiting, caching, etc.

## 📚 Configuration Guides

### **Getting Started**
| Guide | Purpose | Time | When to Use |
|-------|---------|------|-------------|
| **[Basic Configuration](basic.md)** | Essential setup options | 5 min | First time setup |
| **[Database Configuration](database.md)** | Database connection and settings | 10 min | Setting up persistence |

### **Security & Policies** 
| Guide | Purpose | Time | When to Use |
|-------|---------|------|-------------|
| **[Password Policy](password-policy.md)** 🆕 | Password strength requirements | 10 min | Enhancing security |
| **[Security Configuration](security.md)** | Production security settings | 15 min | Production deployment |

### **Production Ready**
| Guide | Purpose | Time | When to Use |
|-------|---------|------|-------------|
| **[Environment Variables](environment.md)** | Secure configuration management | 10 min | Multiple environments |
| **[Advanced Configuration](advanced.md)** | Performance and customization | 20 min | Complex requirements |

## 🎯 Configuration by Use Case

### **Development Environment**
Quick setup for local development:
```yaml
ricardo:
  auth:
    jwt:
      secret: "dev-secret-key-256-bits-long-for-development-use-only"
      expiration: 86400000  # 1 day
    password-policy:
      min-length: 6         # Relaxed for testing
      require-special-chars: false
```
👉 **See:** [Basic Configuration](basic.md#development-setup)

### **Production Environment**
Secure setup for production:
```yaml
ricardo:
  auth:
    jwt:
      secret: ${JWT_SECRET}     # From environment variable
      expiration: 604800000     # 7 days
    password-policy:
      min-length: 12            # Stronger for production
      require-special-chars: true
```
👉 **See:** [Environment Variables](environment.md), [Security Configuration](security.md)

### **Mobile API Backend**
Optimized for mobile applications:
```yaml
ricardo:
  auth:
    jwt:
      expiration: 2592000000    # 30 days for mobile
    password-policy:
      require-special-chars: false  # Mobile-friendly
```
👉 **See:** [Mobile API Example](../examples/mobile-api.md)

### **High-Security Application**
Maximum security settings:
```yaml
ricardo:
  auth:
    jwt:
      expiration: 3600000       # 1 hour
    password-policy:
      min-length: 15
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      prevent-common-passwords: true
```
👉 **See:** [Security Configuration](security.md), [Password Policy](password-policy.md)

## 🔧 Configuration Management

### **Development Workflow**

1. **Start with basic configuration:**
   ```yaml
   ricardo:
     auth:
       jwt:
         secret: "development-secret-key"
   ```

2. **Add database:**
   ```yaml
   spring:
     datasource:
       url: jdbc:h2:mem:testdb
   ```

3. **Configure password policy:**
   ```yaml
   ricardo:
     auth:
       password-policy:
         min-length: 8
   ```

4. **Move to production:**
   - Replace secrets with environment variables
   - Use production database
   - Strengthen security policies

### **Environment-Specific Configuration**

#### **Using Spring Profiles**
```yaml
# application.yml (default)
ricardo:
  auth:
    jwt:
      secret: "default-secret"

---
# Development profile
spring:
  config:
    activate:
      on-profile: dev
ricardo:
  auth:
    jwt:
      secret: "dev-secret"
      expiration: 86400000

---
# Production profile  
spring:
  config:
    activate:
      on-profile: prod
ricardo:
  auth:
    jwt:
      secret: ${JWT_SECRET}
      expiration: 604800000
```

#### **Using Environment Variables**
```bash
# Development
export RICARDO_AUTH_JWT_SECRET="dev-secret"
export RICARDO_AUTH_JWT_EXPIRATION="86400000"

# Production
export RICARDO_AUTH_JWT_SECRET="prod-secret-from-vault"
export RICARDO_AUTH_JWT_EXPIRATION="604800000"
```

## 🛠 Configuration Validation

### **Check Your Configuration**

1. **Verify configuration is loaded:**
   ```bash
   curl http://localhost:8080/actuator/configprops | grep ricardo
   ```

2. **Test basic functionality:**
   ```bash
   # Test user creation
   curl -X POST http://localhost:8080/api/users/create \
     -H "Content-Type: application/json" \
     -d '{"username":"test","email":"test@example.com","password":"TestPass@123!"}'
   ```

3. **Check health status:**
   ```bash
   curl http://localhost:8080/actuator/health
   ```

### **Common Configuration Issues**

| Issue | Solution | Guide |
|-------|----------|-------|
| JWT secret not set | Add `ricardo.auth.jwt.secret` | [Basic Configuration](basic.md) |
| Database connection fails | Check datasource configuration | [Database Configuration](database.md) |
| Password validation errors | Check password policy settings | [Password Policy](password-policy.md) |
| Authentication fails | Verify JWT secret consistency | [Security Configuration](security.md) |

## 📊 Configuration Templates

### **Minimal Template**
```yaml
# Absolute minimum configuration
ricardo:
  auth:
    jwt:
      secret: "${JWT_SECRET:your-fallback-secret-here}"

spring:
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
  jpa:
    hibernate:
      ddl-auto: create-drop
```

### **Complete Template**
```yaml
# Comprehensive configuration example
spring:
  application:
    name: my-app
  
  datasource:
    url: ${DATABASE_URL:jdbc:h2:mem:testdb}
    username: ${DATABASE_USERNAME:sa}
    password: ${DATABASE_PASSWORD:password}
    driver-class-name: ${DATABASE_DRIVER:org.h2.Driver}
  
  jpa:
    hibernate:
      ddl-auto: ${DDL_AUTO:create-drop}
    show-sql: ${SHOW_SQL:false}

ricardo:
  auth:
    enabled: ${RICARDO_AUTH_ENABLED:true}
    
    jwt:
      secret: ${JWT_SECRET}
      expiration: ${JWT_EXPIRATION:604800000}
    
    password-policy:
      min-length: ${PASSWORD_MIN_LENGTH:8}
      max-length: ${PASSWORD_MAX_LENGTH:128}
      require-uppercase: ${PASSWORD_REQUIRE_UPPERCASE:true}
      require-lowercase: ${PASSWORD_REQUIRE_LOWERCASE:true}
      require-digits: ${PASSWORD_REQUIRE_DIGITS:true}
      require-special-chars: ${PASSWORD_REQUIRE_SPECIAL_CHARS:true}
      prevent-common-passwords: ${PASSWORD_PREVENT_COMMON:true}
    
    controllers:
      auth:
        enabled: ${AUTH_CONTROLLER_ENABLED:true}
      user:
        enabled: ${USER_CONTROLLER_ENABLED:true}

server:
  port: ${SERVER_PORT:8080}

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics

logging:
  level:
    com.ricardo.auth: ${RICARDO_AUTH_LOG_LEVEL:INFO}
    org.springframework.security: ${SECURITY_LOG_LEVEL:WARN}
```

## 🔗 Quick Links

### **Essential Reading**
- **[Basic Configuration](basic.md)** - Start here for first-time setup
- **[Password Policy](password-policy.md)** 🆕 - Configure password requirements
- **[Environment Variables](environment.md)** - Secure configuration management

### **Production Ready**
- **[Database Configuration](database.md)** - Production database setup
- **[Security Configuration](security.md)** - Production security settings
- **[Advanced Configuration](advanced.md)** - Performance optimization

### **Examples & Troubleshooting**
- **[Configuration Examples](../examples/index.md)** - Real-world configurations
- **[Troubleshooting](../troubleshooting/index.md)** - Common configuration issues

## 🆘 Need Help?

### **Common Questions**
- **"What's the minimum configuration?"** → [Basic Configuration](basic.md#minimum-configuration)
- **"How do I secure for production?"** → [Security Configuration](security.md)
- **"How do I configure passwords?"** → [Password Policy](password-policy.md)
- **"Configuration not working?"** → [Troubleshooting](../troubleshooting/index.md)

### **Get Support**
- 📖 [Full Documentation](../index.md)
- 🐛 [GitHub Issues](https://github.com/RicardoMorim/Auth-Provider/issues)
- 💬 [GitHub Discussions](https://github.com/RicardoMorim/Auth-Provider/discussions)

---

**Ready to configure?** Start with [Basic Configuration](basic.md) for your first setup! 🚀
