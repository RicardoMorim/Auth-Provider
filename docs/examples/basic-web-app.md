# Basic Web Application

**Perfect for:** Learning Ricardo Auth, simple web applications, prototypes  
**Complexity:** ⭐ Easy  
**Time:** 15 minutes  

## What You'll Build

A simple Spring Boot web application with:
- ✅ User registration and login
- ✅ JWT token authentication
- ✅ Protected pages with role-based access
- ✅ Password policy validation
- ✅ Frontend integration examples

## Project Structure

```
my-web-app/
├── src/main/java/com/mycompany/webapp/
│   ├── WebAppApplication.java
│   └── controller/
│       └── HomeController.java
├── src/main/resources/
│   ├── application.yml
│   ├── static/
│   │   └── js/
│   │       └── auth.js
│   └── templates/
│       ├── index.html
│       ├── login.html
│       └── dashboard.html
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
    <artifactId>my-web-app</artifactId>
    <version>1.0.0</version>
    <name>my-web-app</name>
    
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

## Step 2: Configuration (application.yml)

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
      path: /h2-console

# Ricardo Auth configuration
ricardo:
  auth:
    jwt:
      secret: "my-super-secure-development-secret-key-for-webapp-should-be-256-bits"
      expiration: 86400000  # 24 hours for development
    
    # Password policy configuration
    password-policy:
      min-length: 8
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      prevent-common-passwords: true
    
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

## Step 3: Main Application Class

```java
package com.mycompany.webapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main application class for the web app demo.
 * 
 * Ricardo Auth will be auto-configured and ready to use.
 */
@SpringBootApplication
public class WebAppApplication {
    public static void main(String[] args) {
        SpringApplication.run(WebAppApplication.class, args);
    }
}
```

## Step 4: Web Controllers

```java
package com.mycompany.webapp.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Web controller for handling page navigation and rendering.
 */
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
    
    @GetMapping("/register")
    public String register() {
        return "register";
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

## Step 5: Frontend Templates

### Home Page (templates/index.html)
```html
<!DOCTYPE html>
<html>
<head>
    <title>My Web App</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body text-center">
                        <h1 class="card-title">Welcome to My Web App</h1>
                        <p class="card-text">A demo application using Ricardo Auth</p>
                        <div class="d-grid gap-2">
                            <a href="/login" class="btn btn-primary">Login</a>
                            <a href="/register" class="btn btn-outline-secondary">Register</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
```

### Login Page (templates/login.html)
```html
<!DOCTYPE html>
<html>
<head>
    <title>Login - My Web App</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h2 class="card-title text-center mb-4">Login</h2>
                        <form id="loginForm">
                            <div class="mb-3">
                                <label for="email" class="form-label">Email</label>
                                <input type="email" class="form-control" id="email" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" class="form-control" id="password" required>
                            </div>
                            <div id="error" class="alert alert-danger d-none"></div>
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary">Login</button>
                            </div>
                        </form>
                        <div class="text-center mt-3">
                            <a href="/register">Don't have an account? Register here</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="/js/auth.js"></script>
</body>
</html>
```

### Dashboard (templates/dashboard.html)
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Dashboard - My Web App</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#">My Web App</a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">Welcome, <span th:text="${username}">User</span>!</span>
                <button class="btn btn-outline-light btn-sm" onclick="logout()">Logout</button>
            </div>
        </div>
    </nav>
    
    <div class="container mt-5">
        <div class="row">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-body">
                        <h2 class="card-title">Dashboard</h2>
                        <p class="card-text">Welcome to your protected dashboard!</p>
                        <div id="userInfo">
                            <h5>Your Account Information:</h5>
                            <div id="accountDetails">Loading...</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Quick Actions</h5>
                        <div class="d-grid gap-2">
                            <button class="btn btn-outline-primary" onclick="loadUserProfile()">Load Profile</button>
                            <button class="btn btn-outline-info" onclick="testAuthenticatedAPI()">Test API</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="/js/auth.js"></script>
    <script>
        // Load user info on page load
        document.addEventListener('DOMContentLoaded', function() {
            loadUserProfile();
        });
        
        async function loadUserProfile() {
            const user = await authService.getCurrentUser();
            if (user) {
                document.getElementById('accountDetails').innerHTML = `
                    <p><strong>Email:</strong> ${user.username}</p>
                    <p><strong>Roles:</strong> ${user.authorities.join(', ')}</p>
                `;
            }
        }
        
        async function testAuthenticatedAPI() {
            try {
                const response = await fetch('/api/auth/me', {
                    headers: authService.getAuthHeaders()
                });
                
                if (response.ok) {
                    const data = await response.json();
                    alert('API call successful! User: ' + data.username);
                } else {
                    alert('API call failed!');
                }
            } catch (error) {
                alert('Network error: ' + error.message);
            }
        }
    </script>
</body>
</html>
```

## Step 6: JavaScript Authentication Service

### Authentication Service (static/js/auth.js)
```javascript
/**
 * Authentication service for handling JWT tokens and API calls
 */
class AuthService {
    constructor() {
        this.token = sessionStorage.getItem('authToken');
        this.baseUrl = window.location.origin;
    }

    /**
     * Login with email and password
     */
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
            return { success: false, error: 'Network error: ' + error.message };
        }
    }

    /**
     * Register a new user
     */
    async register(username, email, password) {
        try {
            const response = await fetch(`${this.baseUrl}/api/users/create`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, email, password })
            });

            if (response.ok) {
                const data = await response.json();
                return { success: true, user: data };
            } else {
                const error = await response.json();
                return { success: false, error: error.message };
            }
        } catch (error) {
            return { success: false, error: 'Network error: ' + error.message };
        }
    }

    /**
     * Get current authenticated user
     */
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

    /**
     * Logout user
     */
    logout() {
        this.token = null;
        sessionStorage.removeItem('authToken');
        window.location.href = '/login';
    }

    /**
     * Check if user is authenticated
     */
    isAuthenticated() {
        return !!this.token;
    }

    /**
     * Get headers for authenticated requests
     */
    getAuthHeaders() {
        return {
            'Authorization': `Bearer ${this.token}`,
            'Content-Type': 'application/json'
        };
    }
}

// Global auth service instance
const authService = new AuthService();

// Global logout function
function logout() {
    authService.logout();
}

// Login form handler
document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('error');
            
            const result = await authService.login(email, password);
            
            if (result.success) {
                window.location.href = '/dashboard';
            } else {
                errorDiv.textContent = result.error;
                errorDiv.classList.remove('d-none');
            }
        });
    }

    // Register form handler
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const errorDiv = document.getElementById('error');
            
            if (password !== confirmPassword) {
                errorDiv.textContent = 'Passwords do not match';
                errorDiv.classList.remove('d-none');
                return;
            }
            
            const result = await authService.register(username, email, password);
            
            if (result.success) {
                alert('Registration successful! Please login.');
                window.location.href = '/login';
            } else {
                errorDiv.textContent = result.error;
                errorDiv.classList.remove('d-none');
            }
        });
    }
});
```

## Step 7: Test the Application

### 1. Start the Application
```bash
mvn spring-boot:run
```

### 2. Create a Test User (via API)
```bash
curl -X POST http://localhost:8080/api/users/create \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "TestPass@123!"
  }'
```

### 3. Test Authentication (via API)
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass@123!"
  }'
```

### 4. Access the Web Interface
- Open browser to `http://localhost:8080`
- Try logging in with your test user
- Access the dashboard and test the features

## 🎉 What You've Accomplished

✅ **Working Spring Boot Web Application**  
✅ **JWT Authentication System**  
✅ **User Registration and Login**  
✅ **Protected Pages with Role-Based Access**  
✅ **Frontend Integration with JavaScript**  
✅ **Password Policy Validation**  
✅ **Complete Authentication Flow**

## 🚀 Next Steps

### Enhance Your Application
- Add user profile editing
- Implement password reset functionality
- Add email verification
- Create admin management features

### Production Readiness
- Configure production database (PostgreSQL, MySQL)
- Set up proper JWT secrets via environment variables
- Add HTTPS/SSL configuration
- Implement proper error pages

### Learning More
- **[Mobile API Backend](mobile-api.md)** - Build REST APIs for mobile apps
- **[Configuration Guide](../configuration/index.md)** - Explore all configuration options
- **[Security Guide](../security-guide.md)** - Learn production security best practices

## 🆘 Troubleshooting

### Common Issues
- **"JWT secret not configured"** → Check your `application.yml` configuration
- **"Failed to configure DataSource"** → Ensure H2 dependency is included
- **"Password doesn't meet requirements"** → Use passwords with uppercase, lowercase, digits, and special characters
- **Login fails** → Check the browser developer tools for error messages

### Need Help?
- 📖 [Troubleshooting Guide](../troubleshooting/index.md)
- 💬 [GitHub Discussions](https://github.com/RicardoMorim/Auth-Provider/discussions)

---

🎉 **Congratulations!** You've successfully built a complete web application with Ricardo Auth!
