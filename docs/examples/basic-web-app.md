# Basic Web Application

**Perfect for:** Learning Ricardo Auth, simple web applications, prototypes  
**Complexity:** ⭐ Easy  
**Time:** 15 minutes

---

> **Breaking Changes (v3.0.0):**
> - **UUID Primary Keys:** All user IDs are now UUID instead of Long
> - **Enhanced Decoupling:** New factory pattern for user creation
> - **Repository Types:** Choose between JPA and PostgreSQL implementations
> - **CSRF Protection:** Cross-Site Request Forgery protection now enabled by default (NEW)
> 
> **v2.0.0 Changes:**
> - Authentication now uses secure cookies (`access_token`, `refresh_token`) with `HttpOnly`, `Secure`, and `SameSite`
    flags by default. You must use HTTPS in production or set `ricardo.auth.cookies.access.secure: false` for local
    development only.
> - New blocklist and rate limiting features are available (see below).
> - New `/api/auth/revoke` admin endpoint for revoking tokens (access or refresh).

## What You'll Build

A simple Spring Boot web application with:

- ✅ User registration and login
- ✅ JWT token authentication (via secure cookies)
- ✅ Protected pages with role-based access
- ✅ Password policy validation
- ✅ Frontend integration examples
- ✅ Token blocklist and rate limiting (optional)

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
            <version>3.0.0</version> <!-- Use 3.x for UUID primary keys and enhanced features -->
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
      access-token-expiration: 86400000  # 24 hours for development
      refresh-token-expiration: 604800000 # 7 days
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

server:
  port: 8080

logging:
  level:
    com.ricardo.auth: INFO
```

---

## Step 2.1: Token Blocklist and Rate Limiting (NEW)

- **Token Blocklist:**
    - Prevents usage of revoked tokens (access or refresh). Supports in-memory (default) or Redis for distributed
      setups.
    - Configure with `ricardo.auth.token-blocklist.type: memory|redis`.
- **Rate Limiting:**
    - Protects endpoints from brute-force and abuse. Supports in-memory (default) or Redis for distributed setups.
    - Configure with `ricardo.auth.rate-limiter.type: memory|redis` and set `max-requests` and `time-window-ms`.

---

## Step 2.2: Token Revocation Endpoint (NEW)

Ricardo Auth now provides an admin-only endpoint to revoke any token (access or refresh):

```http
POST /api/auth/revoke
Authorization: Bearer <admin-access-token>
Content-Type: application/json

"<token-to-revoke>"
```

- Only users with `ADMIN` role can call this endpoint.
- Works for both access and refresh tokens.

---

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
    document.addEventListener('DOMContentLoaded', function () {
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

> **Ricardo Auth 3.0.0 Example:**
> This JavaScript example demonstrates cookie-based authentication with CSRF protection. Login and refresh endpoints require CSRF tokens for state-changing operations. All authenticated requests must use `credentials: 'include'` to send cookies and include CSRF tokens in headers.

```javascript
// Utility function to get CSRF token from cookie
function getCsrfToken() {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'XSRF-TOKEN') {
            return decodeURIComponent(value);
        }
    }
    return null;
}

// Login form handler
document.addEventListener('DOMContentLoaded', function () {
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async function (e) {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('error');
            
            try {
                // Login endpoint doesn't require CSRF token (public endpoint)
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({email, password}),
                    credentials: 'include' // Important: send cookies
                });
                
                if (response.ok) {
                    window.location.href = '/dashboard';
                } else {
                    const error = await response.json();
                    errorDiv.textContent = error.message || 'Login failed';
                    errorDiv.classList.remove('d-none');
                }
            } catch (err) {
                errorDiv.textContent = 'Network error: ' + err.message;
                errorDiv.classList.remove('d-none');
            }
        });
    }

    // Register form handler
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', async function (e) {
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
            
            try {
                // User creation endpoint doesn't require CSRF token (public endpoint)
                const response = await fetch('/api/users/create', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, email, password}),
                    credentials: 'include'
                });
                
                if (response.ok) {
                    alert('Registration successful! Please login.');
                    window.location.href = '/login';
                } else {
                    const error = await response.json();
                    errorDiv.textContent = error.message || 'Registration failed';
                    errorDiv.classList.remove('d-none');
                }
            } catch (err) {
                errorDiv.textContent = 'Network error: ' + err.message;
                errorDiv.classList.remove('d-none');
            }
        });
    }
});

// Authentication service with CSRF support
const authService = {
    // Get current user info (requires authentication but not CSRF token for GET)
    async getCurrentUser() {
        try {
            const response = await fetch('/api/auth/me', {
                method: 'GET',
                credentials: 'include'
            });
            if (response.ok) {
                return await response.json();
            }
        } catch (err) {
            console.error('Failed to get current user:', err);
        }
        return null;
    },

    // Refresh token (requires CSRF token)
    async refreshToken() {
        try {
            const csrfToken = getCsrfToken();
            if (!csrfToken) {
                console.warn('CSRF token not found for refresh request');
                return false;
            }

            const response = await fetch('/api/auth/refresh', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-XSRF-TOKEN': csrfToken
                }
            });
            
            return response.ok;
        } catch (err) {
            console.error('Token refresh failed:', err);
            return false;
        }
    },

    // Make authenticated API request with CSRF token
    async authenticatedRequest(url, options = {}) {
        const defaultOptions = {
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };

        // Add CSRF token for state-changing methods
        if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(options.method?.toUpperCase())) {
            const csrfToken = getCsrfToken();
            if (csrfToken) {
                defaultOptions.headers['X-XSRF-TOKEN'] = csrfToken;
            } else {
                console.warn('CSRF token not found for', options.method, 'request to', url);
            }
        }

        try {
            let response = await fetch(url, defaultOptions);
            
            // Handle token expiration
            if (response.status === 401) {
                const refreshed = await this.refreshToken();
                if (refreshed) {
                    // Retry with fresh token and CSRF token
                    const newCsrfToken = getCsrfToken();
                    if (newCsrfToken && defaultOptions.headers['X-XSRF-TOKEN']) {
                        defaultOptions.headers['X-XSRF-TOKEN'] = newCsrfToken;
                    }
                    response = await fetch(url, defaultOptions);
                }
            }
            
            return response;
        } catch (err) {
            console.error('Authenticated request failed:', err);
            throw err;
        }
    }
};

// Logout function with CSRF token
async function logout() {
    try {
        const csrfToken = getCsrfToken();
        const headers = {};
        
        if (csrfToken) {
            headers['X-XSRF-TOKEN'] = csrfToken;
        }

        await fetch('/api/auth/logout', {
            method: 'POST',
            credentials: 'include',
            headers
        });
    } catch (err) {
        console.error('Logout request failed:', err);
    }
    
    window.location.href = '/login';
}

// Example: Using the authenticated request method
async function updateUserProfile(profileData) {
    try {
        const response = await authService.authenticatedRequest('/api/users/profile', {
            method: 'PUT',
            body: JSON.stringify(profileData)
        });
        
        if (response.ok) {
            return await response.json();
        } else {
            throw new Error('Failed to update profile');
        }
    } catch (err) {
        console.error('Profile update failed:', err);
        throw err;
    }
}
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
- **"Token revoked" or 401 after logout** → The token was revoked (blocklist is working as intended)
- **"Rate limit exceeded"** → Too many requests from your IP or user, wait and try again

### Need Help?

- 📖 [Troubleshooting Guide](../troubleshooting/index.md)
- 💬 [GitHub Discussions](https://github.com/RicardoMorim/Auth-Provider/discussions)

---

🎉 **Congratulations!** You've successfully built a complete web application with Ricardo Auth!
