# Cookie Authentication Guide

## Overview

The Auth Provider implements secure cookie-based authentication as the **recommended approach** for web applications.
This guide explains how cookies are configured, managed, and secured.

## 🍪 Cookie Implementation

### Access Token Cookie

- **Name**: `access_token`
- **Path**: `/` (available to all application routes)
- **Expiration**: Matches JWT access token expiration (default: 15 minutes)
- **Security**: `httpOnly=true`, `secure=true`, `sameSite=Strict`

### Refresh Token Cookie

- **Name**: `refresh_token`
- **Path**: `/api/auth/refresh` (restricted to refresh endpoint only)
- **Expiration**: Matches JWT refresh token expiration (default: 7 days)
- **Security**: `httpOnly=true`, `secure=true`, `sameSite=Strict`

## 🔒 Security Features

### HttpOnly Protection

```java
// Cookies are marked as httpOnly=true
ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", accessToken)
    .httpOnly(true)  // Prevents JavaScript access (XSS protection)
    .build();
```

**Benefits:**

- ✅ **XSS Protection**: Cookies cannot be accessed via `document.cookie`
- ✅ **Automatic Management**: Browser handles cookie storage and transmission
- ✅ **No Manual Storage**: No need for localStorage or sessionStorage

### Secure Flag

```java
// Automatically enabled when HTTPS is detected
.secure(authProperties.getCookies().getAccess().isSecure())
```

**Auto-Detection:**

- ✅ **HTTPS**: `secure=true` when running on HTTPS
- ✅ **Development**: Can be disabled for localhost development
- ✅ **Proxy Support**: Detects `X-Forwarded-Proto` headers

### SameSite Protection

```java
// CSRF protection via SameSite attribute
.sameSite(authProperties.getCookies().getAccess().getSameSite().getValue())
```

**Options:**

- **Strict** (default): Maximum protection, no cross-site requests
- **Lax**: Allows some cross-site navigation
- **None**: Requires `secure=true`, allows all cross-site requests

## ⚙️ Configuration

### Basic Configuration

```yaml
ricardo:
  auth:
    cookies:
      access:
        secure: true      # Auto-detected based on HTTPS
        http-only: true   # Always enabled for security
        same-site: Strict # CSRF protection
        path: /           # Available to all routes
      refresh:
        secure: true
        http-only: true
        same-site: Strict
        path: /api/auth/refresh  # Restricted path
    redirect-https: true  # Enforce HTTPS in production
```

### Environment-Specific Settings

#### Development

```yaml
ricardo:
  auth:
    cookies:
      access:
        secure: false     # Allow HTTP for localhost
      refresh:
        secure: false
    redirect-https: false
```

#### Production

```yaml
ricardo:
  auth:
    cookies:
      access:
        secure: true      # Require HTTPS
        same-site: Strict # Maximum protection
      refresh:
        secure: true
        same-site: Strict
    redirect-https: true  # Force HTTPS redirect
```

## 🔄 Authentication Flow

### 1. Login

```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**

```http
HTTP/1.1 200 OK
Set-Cookie: access_token=eyJ...; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=900
Set-Cookie: refresh_token=eyJ...; HttpOnly; Secure; SameSite=Strict; Path=/api/auth/refresh; Max-Age=604800
```

### 2. Authenticated Requests

```bash
GET /api/auth/me
# Cookies automatically sent by browser
Cookie: access_token=eyJ...
```

### 3. Token Refresh

```bash
POST /api/auth/refresh
# Refresh cookie automatically sent by browser
Cookie: refresh_token=eyJ...
```

**Response:**

```http
HTTP/1.1 200 OK
Set-Cookie: access_token=newToken...; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=900
Set-Cookie: refresh_token=newRefreshToken...; HttpOnly; Secure; SameSite=Strict; Path=/api/auth/refresh; Max-Age=604800
```

### 4. Logout

```bash
POST /api/auth/logout
Cookie: access_token=eyJ...; refresh_token=eyJ...
```

**Response:**

```http
HTTP/1.1 200 OK
Set-Cookie: access_token=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0
Set-Cookie: refresh_token=; HttpOnly; Secure; SameSite=Strict; Path=/api/auth/refresh; Max-Age=0
```

## 🌐 Frontend Integration

### JavaScript/Fetch API

```javascript
// Login
const login = async (email, password) => {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
    credentials: 'include'  // Important: include cookies
  });
  return response.ok;
};

// Authenticated requests
const getProfile = async () => {
  const response = await fetch('/api/auth/me', {
    credentials: 'include'  // Important: include cookies
  });
  return response.json();
};

// Token refresh (automatic)
const refreshToken = async () => {
  const response = await fetch('/api/auth/refresh', {
    method: 'POST',
    credentials: 'include'  // Refresh cookie sent automatically
  });
  return response.ok;
};
```

### Axios Configuration

```javascript
import axios from 'axios';

// Configure axios to always include cookies
const api = axios.create({
  withCredentials: true  // Include cookies with all requests
});

// Usage
await api.post('/api/auth/login', { email, password });
await api.get('/api/auth/me');  // Cookies sent automatically
```

### React/Next.js Hook

```javascript
const useAuth = () => {
  const apiCall = useCallback(async (url, options = {}) => {
    const response = await fetch(url, {
      ...options,
      credentials: 'include'  // Always include cookies
    });
    
    // Handle token refresh on 401
    if (response.status === 401) {
      const refreshed = await fetch('/api/auth/refresh', {
        method: 'POST',
        credentials: 'include'
      });
      
      if (refreshed.ok) {
        // Retry original request
        return fetch(url, { ...options, credentials: 'include' });
      }
    }
    
    return response;
  }, []);
  
  return { apiCall };
};
```

## 🛡️ Security Validation

The system includes automatic cookie security validation:

### JwtAuthFilter Validation

```java
private boolean validateCookieSecurity(HttpServletRequest request) {
    // Validate HTTPS when secure=true
    if (cookieConfig.isSecure() && !request.isSecure()) {
        // Check for reverse proxy headers
        String forwardedProto = request.getHeader("X-Forwarded-Proto");
        if (!"https".equalsIgnoreCase(forwardedProto)) {
            logger.warn("Secure cookie on non-HTTPS connection");
            return false;
        }
    }
    return true;
}
```

### Path Validation

```java
// Validate cookie path restrictions
String expectedPath = cookieConfig.getPath();
String requestPath = request.getRequestURI();
if (!requestPath.startsWith(expectedPath)) {
    logger.warn("Cookie path mismatch");
}
```

## 🔧 Troubleshooting

### Common Issues

#### Cookies Not Being Set

- ✅ Check `credentials: 'include'` in fetch requests
- ✅ Verify HTTPS configuration matches cookie settings
- ✅ Ensure SameSite policy allows your request context

#### Authentication Failing

- ✅ Verify cookies are being sent: check Network tab in browser
- ✅ Check cookie path restrictions
- ✅ Verify HTTPS/HTTP mismatch

#### CORS Issues

```yaml
# Add to your configuration
spring:
  web:
    cors:
      allowed-origins: "https://yourdomain.com"
      allowed-credentials: true
```

#### Development Setup

```yaml
# For localhost development
ricardo:
  auth:
    cookies:
      access:
        secure: false
      refresh:
        secure: false
    redirect-https: false
```

## 📝 Best Practices

### ✅ Recommended

- Use cookie authentication for web applications
- Enable `httpOnly=true` always
- Use `secure=true` in production (HTTPS)
- Set `sameSite=Strict` for maximum protection
- Include `credentials: 'include'` in all fetch requests
- Use path restrictions for refresh tokens

### ❌ Avoid

- Disabling `httpOnly` (allows XSS attacks)
- Using `secure=false` in production
- Storing tokens in localStorage or sessionStorage
- Manual cookie manipulation in JavaScript
- Disabling HTTPS redirect in production

## 🔗 Related Documentation

- [Security Guide](security-guide.md)
- [Swagger API Documentation](swagger-api-documentation.md)
- [Configuration Guide](configuration/index.md)
- [Troubleshooting](troubleshooting/authentication.md)
