# Examples Overview

This section provides practical, real-world examples for implementing Ricardo Auth in different types of applications.

## 🚀 Quick Navigation

### By Application Type
- **[Basic Web Application](basic-web-app.md)** ⭐ - Simple web app with authentication *(15 min)*
- **[Microservices Architecture](microservices.md)** ⭐⭐⭐ - Distributed authentication across services *(45 min)*
- **[Mobile API Backend](mobile-api.md)** ⭐⭐ - Backend for mobile applications *(25 min)*
- **[E-commerce Platform](ecommerce.md)** ⭐⭐ - Business applications with complex auth *(35 min)*
- **[Multi-Tenant Application](multi-tenant.md)** ⭐⭐⭐ - Tenant-aware authentication *(40 min)*
- **[Social Media Platform](social-media.md)** ⭐⭐ - User profiles and social features *(30 min)*

### By Feature Focus
- **[Password Policy Examples](password-policy.md)** 🆕 - Password validation examples and configuration
- **[Refresh Token Examples](refresh-token.md)** 🆕 - Token refresh patterns and frontend integration
- **[Custom Integrations](custom-integrations.md)** ⭐⭐⭐ - Advanced customization scenarios

### By Complexity Level

#### 🟢 **Beginner** (⭐)
Perfect if you're new to Ricardo Auth or Spring Security
- [Basic Web Application](basic-web-app.md) - Learn the fundamentals

#### 🟡 **Intermediate** (⭐⭐)
Good for developers with some Spring experience
- [Mobile API Backend](mobile-api.md) - REST API patterns
- [E-commerce Platform](ecommerce.md) - Business application patterns
- [Social Media Platform](social-media.md) - User-centric features

#### 🔴 **Advanced** (⭐⭐⭐)
For experienced developers building complex systems
- [Microservices Architecture](microservices.md) - Distributed systems
- [Multi-Tenant Application](multi-tenant.md) - Multi-tenancy patterns
- [Custom Integrations](custom-integrations.md) - Deep customization

## 🎯 Choose Your Path

### **I want to learn Ricardo Auth**
👉 Start with [Basic Web Application](basic-web-app.md)

### **I'm building a REST API**
👉 Check out [Mobile API Backend](mobile-api.md)

### **I need enterprise-scale auth**
👉 See [Microservices Architecture](microservices.md)

### **I'm building an online store**
👉 Look at [E-commerce Platform](ecommerce.md)

### **I need tenant isolation**
👉 Review [Multi-Tenant Application](multi-tenant.md)

### **I want social features**
👉 Explore [Social Media Platform](social-media.md)

### **I need custom behavior**
👉 Study [Custom Integrations](custom-integrations.md)

## 📋 Before You Start

### Prerequisites
- Java 17+
- Spring Boot 3.0+
- Maven or Gradle
- Basic understanding of Spring Security (helpful but not required)

### What You'll Need
```xml
<!-- Always required -->
<dependency>
    <groupId>io.github.ricardomorim</groupId>
    <artifactId>auth-spring-boot-starter</artifactId>
    <version>1.1.0</version>
</dependency>

<!-- Required for database -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
```

### Basic Configuration Template
```yaml
# Minimal configuration for all examples
ricardo:
  auth:
    jwt:
      secret: "your-256-bit-secret-key-here"
      
spring:
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
    username: sa
    password: password
  jpa:
    hibernate:
      ddl-auto: create-drop
```

## 💡 Tips for Success

### 🔑 **Security Best Practices**
- Always use environment variables for secrets in production
- Configure strong password policies
- Use HTTPS in production
- Implement proper CORS configuration

### 🧪 **Testing Strategy**
- Start with H2 database for quick prototyping
- Use different JWT expiration times for different environments
- Test authentication flows early and often

### 📈 **Performance Considerations**
- Configure database connection pooling for production
- Consider JWT token expiration times based on your use case
- Monitor authentication endpoint performance

## 🆘 Need Help?

### Common Starting Points
- **Can't get started?** → [Basic Web Application](basic-web-app.md)
- **Authentication fails?** → Check [Troubleshooting Guide](../troubleshooting/index.md)
- **Need custom behavior?** → See [Custom Integrations](custom-integrations.md)

### Get Support
- 📖 [Documentation Index](../index.md) - All guides
- 🐛 [Troubleshooting](../troubleshooting/index.md) - Common issues
- 💬 [GitHub Discussions](https://github.com/RicardoMorim/Auth-Provider/discussions) - Ask questions

---

**Ready to get started?** Pick an example above and dive in! 🚀
