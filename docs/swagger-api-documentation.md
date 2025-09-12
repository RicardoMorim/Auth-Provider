# API Documentation with Swagger

## Overview

The Auth Provider includes comprehensive OpenAPI 3.0 documentation with Swagger UI for easy API testing and integration. The system uses **secure HTTP-only cookie authentication** for maximum security and seamless browser integration.

## Accessing Swagger UI

After starting your Spring Boot application, you can access the Swagger UI at:

- **Development**: `http://localhost:8080/swagger-ui/index.html`
- **OpenAPI JSON**: `http://localhost:8080/v3/api-docs`

## 🍪 Cookie Authentication

**How it works:**
- JWT tokens are stored as secure HTTP-only cookies
- Cookies are automatically sent by the browser with each request
- Tokens are protected with `httpOnly=true`, `secure=true`, and `sameSite=Strict`
- **Immune to XSS attacks** since cookies are not accessible via JavaScript
- **CORS is properly configured** for cross-origin requests

**Configuration:**
- Access token cookie: `access_token` (path: `/`)
- Refresh token cookie: `refresh_token` (path: `/api/auth/refresh`)
- All cookies use maximum security settings when HTTPS is enabled

**In Swagger UI:**
1. Use the login endpoint to authenticate
2. Cookies are automatically set and managed by the browser
3. Protected endpoints work automatically (no manual token entry needed)
4. **No "Authorize" button needed** - authentication is seamless

### Example Login Request

```json
{
  "email": "admin@example.com", 
  "password": "securePassword123"
}
```

## Security Features

### Cookie Security Settings

All authentication cookies include:

- **httpOnly=true** - Prevents JavaScript access (XSS protection)
- **secure=true** - Only sent over HTTPS (when HTTPS is enabled)
- **sameSite=Strict** - CSRF protection
- **Path restrictions** - Access token for all paths, refresh token only for refresh endpoint

### Auto-Configuration

The system automatically configures cookie security based on your settings:

```yaml
ricardo:
  auth:
    cookies:
      access:
        secure: true      # Auto-detected based on HTTPS
        http-only: true   # Always true for security
        same-site: Strict # CSRF protection
        path: /
      refresh:
        secure: true
        http-only: true
        same-site: Strict
        path: /api/auth/refresh
```

## 🌐 CORS Support

CORS is automatically configured to work with cookie authentication:

```yaml
# CORS is handled automatically by Spring Security
# Supports:
- Cross-origin requests with credentials
- Automatic CSRF token handling  
- Preflight request support
- Custom origin patterns
```

### Frontend Integration

```javascript
// All requests automatically include cookies
fetch('/api/auth/me', {
  credentials: 'include'  // Important: include cookies
});

// Login
fetch('/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password }),
  credentials: 'include'  // Cookies will be set automatically
});
```

## API Endpoints Documentation

### Authentication Endpoints
- `POST /api/auth/login` - User login with credentials
- `POST /api/auth/refresh` - Refresh JWT token
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Get current user information

### User Management Endpoints
- `GET /api/users` - List all users (Admin only)
- `POST /api/users` - Create new user (Admin only)
- `GET /api/users/{userId}` - Get user by ID
- `PUT /api/users/{userId}` - Update user
- `DELETE /api/users/{userId}` - Delete user (Admin only)

### Role Management Endpoints
- `GET /api/users/{userId}/roles` - Get user roles
- `POST /api/users/{userId}/roles` - Add role to user
- `DELETE /api/users/{userId}/roles` - Remove role from user
- `PUT /api/users/{userId}/roles/bulk` - Bulk update user roles

### Password Reset Endpoints
- `POST /api/auth/password-reset` - Request password reset
- `PUT /api/auth/password-reset` - Complete password reset

## Security Features

### Role-Based Access Control
- **ADMIN**: Full access to all endpoints
- **USER**: Limited access to own resources
- **Custom Permissions**: USER_READ, USER_WRITE, etc.

### Input Validation
- All endpoints include comprehensive input validation
- Sanitization to prevent injection attacks
- Rate limiting on sensitive operations

### Error Handling
- Standardized error responses
- Security-conscious error messages
- Proper HTTP status codes

## Testing with Postman

You can also import the OpenAPI specification into Postman:

1. Open Postman
2. Click "Import"
3. Use the URL: `http://localhost:8080/v3/api-docs`
4. Postman will automatically create a collection with all endpoints

## Development Notes

### OpenAPI Annotations Used
- `@Tag` - Controller-level grouping
- `@Operation` - Endpoint descriptions
- `@ApiResponses` - Response documentation
- `@Parameter` - Parameter descriptions
- `@SecurityRequirement` - Authentication requirements

### Configuration
- JWT authentication scheme configured
- Multiple server environments supported
- Comprehensive API metadata included

## Common Use Cases

### 1. User Registration Flow
1. Admin creates user via `POST /api/users`
2. User logs in via `POST /api/auth/login`
3. User gets profile via `GET /api/auth/me`

### 2. Role Assignment
1. Get user roles via `GET /api/users/{userId}/roles`
2. Add role via `POST /api/users/{userId}/roles`
3. Verify changes via `GET /api/users/{userId}/roles`

### 3. Password Reset
1. Request reset via `POST /api/auth/password-reset`
2. Complete reset via `PUT /api/auth/password-reset`

## Troubleshooting

### Common Issues
- **401 Unauthorized**: Check JWT token format and validity
- **403 Forbidden**: Verify user has required role/permissions
- **404 Not Found**: Confirm endpoint URL and method
- **400 Bad Request**: Check request body format and required fields

### Token Format
Ensure your Authorization header follows this format:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Support

For additional help, refer to:
- [Security Guide](security-guide.md)
- [Getting Started](getting-started.md)
- [Troubleshooting](troubleshooting/index.md)
