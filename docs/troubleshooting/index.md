# Troubleshooting Overview

Quick help for solving common Ricardo Auth issues. **Use Ctrl+F to search** for your specific error message.

## 🆘 Emergency Quick Fixes

**App won't start?** → [Startup Issues](startup-issues.md)  
**Login fails?** → [Authentication Issues](authentication.md)  
**Token refresh fails?** → [Refresh Token Issues](refresh-token.md)  
**Password rejected?** → [Password Policy Issues](password-policy.md)  
**Database errors?** → [Database Issues](database.md)  
**Performance problems?** → [Performance Issues](performance.md)

---

## 📋 Issue Categories

### 🚀 **Startup & Configuration**

| Issue                     | Guide                               | Common Causes                                |
|---------------------------|-------------------------------------|----------------------------------------------|
| App fails to start        | [Startup Issues](startup-issues.md) | Missing JWT secret, wrong dependencies       |
| Bean creation errors      | [Startup Issues](startup-issues.md) | Configuration conflicts, missing annotations |
| Database connection fails | [Database Issues](database.md)      | Wrong URL, missing drivers                   |

### 🔐 **Authentication & Security**

| Issue              | Guide                                      | Common Causes                     |
|--------------------|--------------------------------------------|-----------------------------------|
| Login always fails | [Authentication Issues](authentication.md) | Wrong credentials, user not found |
| JWT token invalid  | [Authentication Issues](authentication.md) | Expired token, wrong secret       |
| CORS errors        | [Authentication Issues](authentication.md) | Missing CORS configuration        |

### 🔑 **Password Policy**

| Issue                      | Guide                                        | Common Causes                   |
|----------------------------|----------------------------------------------|---------------------------------|
| Password validation errors | [Password Policy Issues](password-policy.md) | Too weak, missing requirements  |
| Common password rejected   | [Password Policy Issues](password-policy.md) | Blacklisted password            |
| Policy too strict          | [Password Policy Issues](password-policy.md) | Wrong environment configuration |

### 🔄 **Refresh Token Issues**

| Issue                   | Guide                                    | Common Causes                  |
|-------------------------|------------------------------------------|--------------------------------|
| Refresh token not found | [Refresh Token Issues](refresh-token.md) | Token expired, database issues |
| Token refresh fails     | [Refresh Token Issues](refresh-token.md) | Invalid token, rotation issues |
| Too many tokens error   | [Refresh Token Issues](refresh-token.md) | Exceeded user limit            |

### 🗄️ **Database & Data**

| Issue                     | Guide                          | Common Causes                         |
|---------------------------|--------------------------------|---------------------------------------|
| Table not found           | [Database Issues](database.md) | Schema not created, wrong DDL setting |
| Connection pool exhausted | [Database Issues](database.md) | Too many connections, leaks           |
| Migration errors          | [Database Issues](database.md) | Version conflicts, manual changes     |

### ⚡ **Performance & Production**

| Issue               | Guide                                | Common Causes                         |
|---------------------|--------------------------------------|---------------------------------------|
| Slow authentication | [Performance Issues](performance.md) | Database queries, connection pool     |
| Memory leaks        | [Performance Issues](performance.md) | Connection leaks, caching issues      |
| High CPU usage      | [Performance Issues](performance.md) | Password hashing, inefficient queries |

## 🔍 Search by Error Message

### Application Startup Errors

-
`Property 'ricardo.auth.jwt.secret' is required` → [JWT Secret Not Configured](startup-issues.md#jwt-secret-not-configured)
- `Failed to configure a DataSource` → [Missing JPA Dependencies](startup-issues.md#missing-jpa-dependencies)
- `Error creating bean` → [Bean Creation Errors](startup-issues.md#bean-creation-errors)

### Authentication Errors

- `Unauthorized` / `401` → [Login Issues](authentication.md#login-always-returns-401-unauthorized)
- `JWT token is missing or invalid` → [Token Issues](authentication.md#jwt-token-not-working)
- `Access to fetch has been blocked by CORS` → [CORS Issues](authentication.md#cors-issues)

### Password Policy Errors

- `Password must be at least X characters` → [Length Requirements](password-policy.md#password-too-short)
- `Password must contain uppercase` → [Character Requirements](password-policy.md#missing-character-types)
- `Password is too common` → [Common Password](password-policy.md#common-password-detected)

### Refresh Token Errors

- `Refresh token not found` → [Token Not Found](refresh-token.md#refresh-token-not-found-error)
- `Invalid or expired refresh token` → [Token Expired](refresh-token.md#invalid-or-expired-refresh-token-error)
- `Too many refresh tokens` → [Token Limit](refresh-token.md#too-many-refresh-tokens-error)

### Database Errors

- `Table 'USER' doesn't exist` → [Schema Issues](database.md#table-not-found)
- `Connection refused` → [Connection Issues](database.md#connection-refused)
- `Unable to acquire JDBC Connection` → [Pool Issues](database.md#connection-pool-exhausted)

## 🛠 Debugging Tools

### Enable Debug Logging

```yaml
logging:
  level:
    com.ricardo.auth: DEBUG
    org.springframework.security: DEBUG
    org.springframework.web: DEBUG
```

### Health Check Endpoint

```bash
curl http://localhost:8080/actuator/health
```

### Check Configuration

```bash
curl http://localhost:8080/actuator/configprops
```

### View Environment

```bash
curl http://localhost:8080/actuator/env
```

## 📊 Monitoring & Diagnostics

### Application Metrics

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,loggers
  endpoint:
    health:
      show-details: always
```

### JWT Token Debugging

```javascript
// Browser console - decode JWT token
function decodeJWT(token) {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
}

// Usage
const token = "your-jwt-token-here";
const payload = decodeJWT(token);
console.log('Token expires at:', new Date(payload.exp * 1000));
```

### Database Connection Testing

```bash
# Test database connection
curl -X GET http://localhost:8080/api/users/exists/test@example.com
```

## 🎯 Issue Resolution Steps

### 1. **Identify the Problem**

- Read the error message carefully
- Check application logs
- Identify which component is failing

### 2. **Gather Information**

- Application configuration
- Environment details
- Steps to reproduce

### 3. **Follow the Guide**

- Use the specific troubleshooting guide for your issue
- Try the quick fixes first
- Follow the detailed debugging steps

### 4. **Verify the Fix**

- Test the functionality
- Check logs for additional errors
- Verify in different environments

### 5. **Prevent Recurrence**

- Document the solution
- Update configuration
- Add monitoring if needed

## 📞 Getting Help

### Before Asking for Help

1. ✅ Search this troubleshooting guide
2. ✅ Check the [Configuration Guide](../configuration/index.md)
3. ✅ Review the [Examples](../examples/index.md)
4. ✅ Enable debug logging and check logs

### Where to Get Help

- 🐛 **[GitHub Issues](https://github.com/RicardoMorim/Auth-Provider/issues)** - Report bugs
- 💬 **[GitHub Discussions](https://github.com/RicardoMorim/Auth-Provider/discussions)** - Ask questions
- 📖 **[Documentation](../index.md)** - Complete guides

### What to Include When Asking for Help

- Ricardo Auth version
- Spring Boot version
- Configuration files (remove secrets!)
- Error messages and stack traces
- Steps to reproduce the issue
- What you've already tried

## 🔧 Common Environment Issues

### Development Environment

- Use H2 database for quick setup
- Enable debug logging
- Use relaxed password policies
- Set JWT secret in configuration

### Testing Environment

- Use in-memory database
- Enable all endpoints
- Use test-specific configuration
- Mock external dependencies

### Production Environment

- Use production database (PostgreSQL, MySQL)
- Set secrets via environment variables
- Enable security headers
- Configure proper CORS
- Set up monitoring and logging

---

## Quick Reference

### Essential Configuration

```yaml
ricardo:
  auth:
    jwt:
      secret: ${JWT_SECRET}
    password-policy:
      min-length: 8
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
```

### Essential Dependencies

```xml
<dependency>
    <groupId>io.github.ricardomorim</groupId>
    <artifactId>auth-spring-boot-starter</artifactId>
    <version>1.1.0</version>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
```

### Quick Test Commands

```bash
# Test user creation
curl -X POST http://localhost:8080/api/users/create \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@example.com","password":"TestPass@123!"}'

# Test login
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPass@123!"}'
```

**Need immediate help?** Start with the [Quick Fixes](#-emergency-quick-fixes) section above! 🚀
