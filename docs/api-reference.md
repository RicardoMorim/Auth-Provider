# API Reference

Complete API reference for the Ricardo Auth Spring Boot Starter endpoints.

## ⚠️ What's New in v4.0.0

**New Features in v4.0.0:**
- **Password Reset System**: OWASP-compliant password reset with email integration
- **Role Management API**: Full CRUD API for role management with proper authorization
- **OpenAPI Integration**: Complete Swagger/OpenAPI documentation at `/swagger-ui.html`
- **Enhanced Input Sanitization**: Advanced input validation and sanitization
- **Better Exception Handling**: Improved error responses and exception management
- **Domain Events**: Comprehensive audit trail with event publishing

**Previous Major Changes:**
- **Cookie Authentication (v2.0.0)**: All authentication uses secure HTTP-only cookies exclusively
- **Rate Limiting & Token Blocklist (v2.0.0)**: Built-in protection against abuse
- **UUID Primary Keys (v3.0.0)**: All entities now use UUID instead of Long for IDs
- **CSRF Protection (v3.0.0)**: Enhanced security with CSRF tokens for state-changing operations

**New API Endpoints in v4.0.0:**
- New password reset endpoints: `/api/auth/reset-request`, `/api/auth/reset/{token}`
- New role management endpoints: `/api/users/{username}/roles`
- Enhanced user management with username-based operations
- Complete OpenAPI documentation with interactive testing

## Base URL

All endpoints are relative to your application's base URL:

```
http://localhost:8080  # Development
https://yourdomain.com # Production
```

## Authentication

Most endpoints are authenticated via secure HTTP-only cookies (`access_token`, `refresh_token`). Public endpoints (e.g., login, password reset, token validation, create) do not require authentication.

**Key Authentication Features:**
- **Cookie-Only (since v2.0.0)**: All authentication uses secure HTTP-only cookies exclusively  
- **No Authorization Headers (since v2.0.0)**: Authorization header authentication removed for security
- **HTTPS Required (since v2.0.0)**: Secure cookies require HTTPS in production environments
- **CSRF Protection (since v3.0.0)**: Enhanced security with CSRF tokens
- **Interactive Documentation (NEW in v4.0.0)**: Complete OpenAPI documentation available at `/swagger-ui.html`
### Frontend Integration Requirements

**Email Configuration Required:**
```yaml
ricardo:
  auth:
    email:
      from-address: "noreply@yourdomain.com"
      from-name: "Your App"
      host: "smtp.gmail.com"
      port: 587

# Standard Spring configuration
spring:
  datasource:
    url: "jdbc:postgresql://localhost:5432/yourdb"
    username: "your_db_user"
    password: "your_db_password"
  mail:
    host: "smtp.gmail.com"
    port: 587
    username: ${MAIL_USERNAME:your_smtp_username}
    password: ${MAIL_PASSWORD:your_smtp_password}
    properties:
      mail:
        smtp:
          auth: true
          starttls:
            enable: true
```

**Optional .env File (only 3 properties supported):**
```env
RICARDO_AUTH_JWT_SECRET=your-256-bit-secret-key-here
MAIL_USERNAME=your_smtp_username
MAIL_PASSWORD=your_smtp_password
```

**Frontend API Calls:**
```javascript
// Ensure credentials (cookies) are included in all requests
fetch('/api/auth/me', {
  credentials: 'include' // Required for cookie authentication
});
```

## CSRF Protection

**NEW in v3.0.0**: CSRF (Cross-Site Request Forgery) protection is now enabled by default for enhanced security.

### How CSRF Works

- CSRF tokens are automatically generated and stored in cookies (`XSRF-TOKEN`)
- JavaScript can read the CSRF token from the cookie (not HttpOnly)
- Include the CSRF token in requests via `X-XSRF-TOKEN` header or `_csrf` form parameter

### Endpoints Exempt from CSRF

The following public endpoints do **not** require CSRF tokens:
- `POST /api/auth/login` (public authentication)
- `POST /api/users/create` (public user registration)

### Endpoints Requiring CSRF

All other authenticated endpoints require CSRF tokens:
- `POST /api/auth/refresh`
- `POST /api/auth/revoke`
- `POST /api/auth/password-reset/request`
- `POST /api/auth/password-reset/confirm`
- `PUT /api/users/update/{id}`
- `DELETE /api/users/delete/{id}`
- `POST /api/roles` (ADMIN)
- `PUT /api/roles/{id}` (ADMIN)
- `DELETE /api/roles/{id}` (ADMIN)

## Endpoint Overview

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required | CSRF |
|--------|----------|-------------|---------------|------|
| POST | `/api/auth/login` | User authentication | No | No |
| POST | `/api/auth/refresh` | Refresh access token | Cookies | Yes |
| POST | `/api/auth/logout` | User logout | Cookies | Yes |
| GET | `/api/auth/me` | Get current user info | Cookies | No |
| POST | `/api/auth/revoke` | Revoke tokens (ADMIN) | Cookies | Yes |

### Password Reset Endpoints

| Method | Endpoint | Description | Auth Required | CSRF |
|--------|----------|-------------|---------------|------|
| POST | `/api/auth/reset-request` | Request password reset | No | No |
| POST | `/api/auth/reset/{token}` | Complete password reset | No | No |
| GET | `/api/auth/reset/{token}/validate` | Validate reset token | No | No |

### User Management Endpoints

| Method | Endpoint | Description | Auth Required | CSRF |
|--------|----------|-------------|---------------|------|
| POST | `/api/users/create` | Create new user | Admin | Yes |
| GET | `/api/users/{username}` | Get user by username | Owner/Admin | No |
| GET | `/api/users/email/{email}` | Get user by email | Admin | No |
| GET | `/api/users/exists/{email}` | Check if user exists | Admin | No |
| GET | `/api/users` | Get all users | Admin | No |
| PUT | `/api/users/update/{username}` | Update user | Owner/Admin | Yes |
| DELETE | `/api/users/delete/{username}` | Delete user | Owner/Admin | Yes |

### Role Management Endpoints (ADMIN Only)

| Method | Endpoint | Description | Auth Required | CSRF |
|--------|----------|-------------|---------------|------|
| GET | `/api/users/{username}/roles` | Get user roles | Admin | No |
| POST | `/api/users/{username}/roles` | Add role to user | Admin | Yes |
| DELETE | `/api/users/{username}/roles` | Remove role from user | Admin | Yes |
| PUT | `/api/users/{username}/roles/bulk` | Bulk update user roles | Admin | Yes |

### Documentation Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/swagger-ui.html` | Interactive API documentation | No |
| GET | `/v3/api-docs` | OpenAPI specification | No |

### Frontend Integration

**JavaScript/Fetch Example:**
```javascript
// Get CSRF token from cookie
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

// Make authenticated request with CSRF token
fetch('/api/auth/refresh', {
    method: 'POST',
    credentials: 'include', // Include cookies
    headers: {
        'Content-Type': 'application/json',
        'X-XSRF-TOKEN': getCsrfToken() // Include CSRF token
    }
});
```

**jQuery Example:**
```javascript
// Set CSRF token for all AJAX requests
$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        if (settings.type === 'POST' || settings.type === 'PUT' || settings.type === 'DELETE') {
            xhr.setRequestHeader('X-XSRF-TOKEN', getCsrfToken());
        }
    }
});
```

**React/Axios Example:**
```javascript
import axios from 'axios';

// Create axios instance with CSRF token interceptor
const api = axios.create({
    withCredentials: true
});

api.interceptors.request.use(config => {
    const token = getCsrfToken();
    if (token) {
        config.headers['X-XSRF-TOKEN'] = token;
    }
    return config;
});
```

### CSRF Error Response

When CSRF token is missing or invalid, you'll receive:

**Response (403 Forbidden):**
```json
{
  "error": "Forbidden",
  "message": "CSRF token missing or invalid",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/auth/refresh"
}
```

## Authentication Endpoints

### POST /api/auth/login

Authenticate a user and receive JWT access and refresh tokens via secure cookies.

#### Request

**Headers:**

```
Content-Type: application/json
```

**Body:**

```json
{
  "email": "string",
  "password": "string"
}
```

#### Response

**Success (200 OK):**

- Sets `access_token` and `refresh_token` cookies (HTTP-only, Secure, SameSite, etc).
- No body is returned by default.

**Error (401 Unauthorized):**

```json
{
  "error": "Unauthorized",
  "message": "Invalid credentials",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/auth/login"
}
```

**Error (400 Bad Request):**

```json
{
  "error": "Bad Request",
  "message": "Email and password are required",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/auth/login"
}
```

#### Example

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "mypassword"
  }'
```

### POST /api/auth/refresh

Refresh an access token using a valid refresh token cookie.

#### Request

- The `refresh_token` must be present as a cookie (not in the body or header).

**Headers:**

```
Cookie: refresh_token=...;
```

#### Response

**Success (200 OK):**

- Sets new `access_token` and (optionally) new `refresh_token` cookies.
- No body is returned by default.

**Error (401 Unauthorized):**

```json
{
  "error": "Unauthorized",
  "message": "Invalid or expired refresh token",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/auth/refresh"
}
```

**Error (400 Bad Request):**

```json
{
  "error": "Bad Request",
  "message": "Refresh token is required",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/auth/refresh"
}
```

#### Example

```bash
curl -X POST http://localhost:8080/api/auth/refresh \
  --cookie "refresh_token=YOUR_REFRESH_TOKEN_HERE"
```

### POST /api/auth/revoke (ADMIN only)

Revokes a token (either access or refresh). Requires ADMIN role. The request body must be a JSON object with a `token`
field specifying the token to revoke.

#### Request

**Headers:**

```
Content-Type: application/json
Cookie: access_token=...;
```

**Body:**

```json
{
  "token": "TOKEN_TO_REVOKE"
}
```

#### Response

**Success (200 OK):**

```json
{
  "message": "Token revoked successfully"
}
```

### POST /api/auth/reset-request

Request a password reset via email. Sends a secure reset token to the user's email address.

#### Request

**Headers:**

```
Content-Type: application/json
```

**Body:**

```json
{
  "email": "user@example.com"
}
```

#### Response

**Success (200 OK):**

```json
{
  "message": "If an account with that email exists, you will receive password reset instructions."
}
```

**Error (429 Too Many Requests) - Rate Limited:**

```json
{
  "message": "Too many requests. Please try again later."
}
```

**Error (400 Bad Request) - Invalid Email:**

```json
{
  "error": "Invalid email format"
}
```

#### Example

```bash
curl -X POST http://localhost:8080/api/auth/reset-request \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

### POST /api/auth/reset/{token}

Complete password reset using the token received via email and set a new password.

#### Request

**Headers:**

```
Content-Type: application/json
```

**Path Parameters:**

- `token` (string): Password reset token from email

**Body:**

```json
{
  "password": "NewSecurePassword123!",
  "confirmPassword": "NewSecurePassword123!"
}
```

#### Response

**Success (200 OK):**

```json
{
  "message": "Password has been reset successfully."
}
```

**Error (400 Bad Request) - Invalid Token:**

```json
{
  "error": "Invalid or expired token."
}
```

**Error (400 Bad Request) - Password Confirmation:**

```json
{
  "error": "Password confirmation does not match."
}
```

**Error (429 Too Many Requests) - Rate Limited:**

```json
{
  "error": "Too many requests. Please try again later."
}
```

#### Example

```bash
curl -X POST http://localhost:8080/api/auth/reset/abc123-def456-ghi789 \
  -H "Content-Type: application/json" \
  -d '{
    "password": "NewSecurePassword123!",
    "confirmPassword": "NewSecurePassword123!"
  }'
```

### GET /api/auth/reset/{token}/validate

Check if a password reset token is valid and not expired (optional endpoint for UI validation).

#### Request

**Path Parameters:**

- `token` (string): Password reset token to validate

#### Response

**Success (200 OK) - Valid Token:**

```json
{
  "valid": true,
  "message": "Token is valid."
}
```

**Success (200 OK) - Invalid Token:**

```json
{
  "valid": false,
  "message": "Token is invalid or expired."
}
```

#### Example

```bash
curl -X GET http://localhost:8080/api/auth/reset/abc123-def456-ghi789/validate
```

### GET /api/auth/me

Get information about the currently authenticated user.

#### Request

**Headers:**

```
Cookie: access_token=...;
```

#### Response

**Success (200 OK):**

```json
{
  "username": "user@example.com",
  "authorities": [
    "ROLE_USER"
  ]
}
```

**Error (401 Unauthorized):**

```json
{
  "error": "Unauthorized",
  "message": "JWT token is missing or invalid",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/auth/me"
}
```

#### Example

```bash
curl -X GET http://localhost:8080/api/auth/me \
  --cookie "access_token=YOUR_ACCESS_TOKEN_HERE"
```

## User Management Endpoints

### POST /api/users/create

Create a new user account with password policy validation.

#### Request

**Headers:**

```
Content-Type: application/json
```

**Body:**

```json
{
  "username": "string",
  // Required: Unique username (3-50 characters)
  "email": "string",
  // Required: Valid email address (unique)
  "password": "string"
  // Required: Password meeting policy requirements
}
```

**Password Requirements with default settings:**

- Minimum 10 characters (configurable)
- At least one uppercase letter
- At least one lowercase letter
- At least one numeric digit
- At least one special character: `!@#$%^&*()`
- Not in common passwords list

#### Response

**Success (201 Created):**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "johndoe",
  "email": "john@example.com"
}
```

**Error (400 Bad Request) - Password Policy Violation:**

```json
{
  "error": "Bad Request",
  "message": "Password must contain at least one uppercase letter",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/users/create"
}
```

**Error (400 Bad Request - Username exists):**

```json
{
  "error": "Bad Request",
  "message": "Username already exists",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/users/create"
}
```

**Error (400 Bad Request - Email exists):**

```json
{
  "error": "Bad Request",
  "message": "Email already exists",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/users/create"
}
```

#### Example

```bash
curl -X POST http://localhost:8080/api/users/create \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "email": "john@example.com", 
    "password": "SecurePass@123!"
  }'
```

**Valid Password Examples:**

- `MySecure@Pass123!`
- `StrongP@ssw0rd`
- `Secure123!@#`

**Invalid Password Examples:**

- `password123` (no uppercase, no special chars)
- `PASSWORD123` (no lowercase)
- `MyPassword` (no digits, no special chars)
- `123456` (too common)

### GET /api/users/{id}

Get user information by ID.

#### Request

**Headers:**

```
Cookie: access_token=YOUR_ACCESS_TOKEN_HERE;
```

> **Note:** The `Authorization` header is not supported for this endpoint. Use the `access_token` cookie.

**Path Parameters:**

- `id` (UUID string): User ID (format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)

#### Response

**Success (200 OK):**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "johndoe",
  "email": "john@example.com"
}
```

**Error (404 Not Found):**

```json
{
  "error": "Not Found",
  "message": "User not found with id: 999",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/users/999"
}
```

#### Example

```bash
curl -X GET http://localhost:8080/api/users/550e8400-e29b-41d4-a716-446655440000 \
  --cookie "access_token=YOUR_ACCESS_TOKEN_HERE"
```

### GET /api/users/email/{email}

Get user information by email address.

#### Request

**Headers:**

```
Cookie: access_token=YOUR_ACCESS_TOKEN_HERE;
```

> **Note:** The `Authorization` header is not supported for this endpoint. Use the `access_token` cookie.

**Path Parameters:**

- `email` (string): User email address

#### Response

**Success (200 OK):**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "johndoe",
  "email": "john@example.com"
}
```

**Error (404 Not Found):**

```json
{
  "error": "Not Found",
  "message": "User not found with email: nonexistent@example.com",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/users/email/nonexistent@example.com"
}
```

#### Example

```bash
curl -X GET http://localhost:8080/api/users/email/john@example.com \
  --cookie "access_token=YOUR_ACCESS_TOKEN_HERE"
```

### GET /api/users/exists/{email}

Check if a user exists by email address.

#### Request

**Path Parameters:**

- `email` (string): Email address to check

#### Response

**Success (200 OK):**

```json
true
```

or

```json
false
```

#### Example

```bash
curl -X GET http://localhost:8080/api/users/exists/john@example.com
```

### PUT /api/users/update/{id}

Update user information.

**Authorization Required:** Must be the user owner or have ADMIN role.

#### Request

**Headers:**

```
Cookie: access_token=YOUR_ACCESS_TOKEN_HERE;
Content-Type: application/json
```

> **Note:** The `Authorization` header is not supported for this endpoint. Use the `access_token` cookie.

**Path Parameters:**

- `id` (UUID string): User ID to update (format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)

**Body:**

```json
{
  "username": "string",
  // Optional: New username
  "email": "string",
  // Optional: New email
  "password": "string"
  // Optional: New password
}
```

#### Response

**Success (200 OK):**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "johnsmith",
  "email": "johnsmith@example.com"
}
```

**Error (403 Forbidden):**

```json
{
  "error": "Forbidden",
  "message": "Access denied: You can only update your own profile",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/users/update/1"
}
```

#### Example

```bash
curl -X PUT http://localhost:8080/api/users/update/550e8400-e29b-41d4-a716-446655440000 \
  --cookie "access_token=YOUR_ACCESS_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johnsmith",
    "email": "johnsmith@example.com"
  }'
```

### DELETE /api/users/delete/{id}

Delete a user account.

**Authorization Required:** Must be the user owner or have ADMIN role.

#### Request

**Headers:**

```
Cookie: access_token=YOUR_ACCESS_TOKEN_HERE;
```

> **Note:** The `Authorization` header is not supported for this endpoint. Use the `access_token` cookie.

**Path Parameters:**

- `id` (UUID string): User ID to delete (format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)

#### Response

**Success (204 No Content):**

```
(Empty response body)
```

**Error (404 Not Found):**

```json
{
  "error": "Not Found",
  "message": "User not found with id: 550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/users/delete/550e8400-e29b-41d4-a716-446655440000"
}
```

**Error (403 Forbidden):**

```json
{
  "error": "Forbidden",
  "message": "Access denied: You can only delete your own profile",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/users/delete/1"
}
```

#### Example

```bash
curl -X DELETE http://localhost:8080/api/users/delete/550e8400-e29b-41d4-a716-446655440000 \
  --cookie "access_token=YOUR_ACCESS_TOKEN_HERE"
```

## Role Management Endpoints

**Note:** All role management endpoints require ADMIN role and authentication via cookies.

### GET /api/users/{username}/roles

Get all roles assigned to a specific user by username.

#### Request

**Headers:**

```
Cookie: access_token=YOUR_ACCESS_TOKEN_HERE;
```

**Path Parameters:**

- `username` (string): Username (not user ID)

#### Response

**Success (200 OK):**

```json
{
  "userId": "550e8400-e29b-41d4-a716-446655440000",
  "username": "johndoe",
  "email": "john@example.com",
  "roles": ["USER", "MODERATOR"]
}
```

**Error (404 Not Found):**

```json
{
  "error": "User not found"
}
```

**Error (403 Forbidden):**

```json
{
  "error": "Access denied - Admin role required"
}
```

#### Example

```bash
curl -X GET http://localhost:8080/api/users/johndoe/roles \
  --cookie "access_token=YOUR_ADMIN_ACCESS_TOKEN_HERE"
```

### POST /api/users/{username}/roles

Add a role to a specific user by username.

#### Request

**Headers:**

```
Content-Type: application/json
Cookie: access_token=YOUR_ACCESS_TOKEN_HERE;
```

**Path Parameters:**

- `username` (string): Username (not user ID)

**Body:**

```json
{
  "roleName": "MODERATOR",
  "reason": "Promoted to moderator for excellent community management"
}
```

#### Response

**Success (200 OK):**

```json
{
  "message": "Role added successfully.",
  "username": "johndoe",
  "role": "MODERATOR"
}
```

**Error (400 Bad Request) - Role Already Assigned:**

```json
{
  "error": "User already has role: MODERATOR"
}
```

**Error (404 Not Found) - User Not Found:**

```json
{
  "error": "User not found: johndoe"
}
```

**Error (404 Not Found) - Role Not Found:**

```json
{
  "error": "Role not found: MODERATOR"
}
```

#### Example

```bash
curl -X POST http://localhost:8080/api/users/johndoe/roles \
  --cookie "access_token=YOUR_ADMIN_ACCESS_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "roleName": "MODERATOR",
    "reason": "Promoted for excellent community management"
  }'
```

### DELETE /api/users/{username}/roles

Remove a role from a specific user by username.

#### Request

**Headers:**

```
Content-Type: application/json
Cookie: access_token=YOUR_ACCESS_TOKEN_HERE;
```

**Path Parameters:**

- `username` (string): Username (not user ID)

**Body:**

```json
{
  "roleName": "MODERATOR",
  "reason": "Role no longer needed"
}
```

#### Response

**Success (200 OK):**

```json
{
  "message": "Role removed successfully.",
  "username": "johndoe",
  "role": "MODERATOR"
}
```

**Error (400 Bad Request) - Role Not Assigned:**

```json
{
  "error": "User does not have role: MODERATOR"
}
```

#### Example

```bash
curl -X DELETE http://localhost:8080/api/users/johndoe/roles \
  --cookie "access_token=YOUR_ADMIN_ACCESS_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "roleName": "MODERATOR",
    "reason": "Role no longer needed"
  }'
```

### PUT /api/users/{username}/roles/bulk

Update multiple role assignments for a user in a single operation.

#### Request

**Headers:**

```
Content-Type: application/json
Cookie: access_token=YOUR_ACCESS_TOKEN_HERE;
```

**Path Parameters:**

- `username` (string): Username (not user ID)

**Body:**

```json
{
  "rolesToAdd": ["MODERATOR", "PREMIUM"],
  "rolesToRemove": ["BASIC"],
  "reason": "User upgrade and promotion"
}
```

#### Response

**Success (200 OK):**

```json
{
  "message": "Roles updated successfully.",
  "username": "johndoe",
  "addedRoles": "MODERATOR, PREMIUM",
  "removedRoles": "BASIC"
}
```

#### Example

```bash
curl -X PUT http://localhost:8080/api/users/johndoe/roles/bulk \
  --cookie "access_token=YOUR_ADMIN_ACCESS_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "rolesToAdd": ["MODERATOR", "PREMIUM"],
    "rolesToRemove": ["BASIC"],
    "reason": "User upgrade and promotion"
  }'
```

## Error Responses

### Common Error Formats

All error responses follow this structure:

```json
{
  "error": "string",
  // HTTP status text
  "message": "string",
  // Detailed error message
  "timestamp": "string",
  // ISO 8601 timestamp
  "path": "string"
  // Request path that caused the error
}
```

### HTTP Status Codes

| Status Code | Description           | Common Causes                                   |
|-------------|-----------------------|-------------------------------------------------|
| 200         | OK                    | Successful GET requests                         |
| 201         | Created               | Successful POST requests                        |
| 204         | No Content            | Successful DELETE requests                      |
| 400         | Bad Request           | Invalid request data, validation errors         |
| 401         | Unauthorized          | Missing or invalid JWT token, wrong credentials |
| 403         | Forbidden             | Insufficient permissions                        |
| 404         | Not Found             | Resource doesn't exist                          |
| 409         | Conflict              | Resource already exists (username/email taken)  |
| 500         | Internal Server Error | Server-side errors                              |

### Validation Errors

When request validation fails, you'll receive detailed error information:

```json
{
  "error": "Bad Request",
  "message": "Validation failed",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/users/create",
  "fieldErrors": [
    {
      "field": "email",
      "message": "must be a well-formed email address"
    },
    {
      "field": "password",
      "message": "must not be blank"
    }
  ]
}
```

## Rate Limiting

The API implements rate limiting (in-memory or Redis). When rate limited, you'll receive:

**Response (429 Too Many Requests):**

```json
{
  "error": "Too Many Requests",
  "message": "Rate limit exceeded. Try again in 60 seconds.",
  "timestamp": "2024-01-15T10:30:00Z",
  "retryAfter": 60
}
```

## Token Blocklist (Revocation)

- Tokens can be revoked instantly (logout, admin revoke, etc).
- Blocklist is implemented in-memory or with Redis.
- Revoked tokens are rejected for all endpoints.
- Use `/api/auth/revoke` to revoke any token (access or refresh).

## Cookie Security (BREAKING CHANGE)

- All tokens are now sent via HTTP-only, Secure cookies.
- SameSite and Path are configurable.
- HTTPS is required in production for Secure cookies.
- The Authorization header is no longer used for authentication.

> **Note:**
> If you are integrating with a third-party frontend, mobile app, or any cross-domain/embedded context where cookies are
> the only authentication method, you **must** set `SameSite=None` and `Secure=true` for the relevant cookies. This is
> required for browsers to send cookies in cross-site requests and is essential for proper login and session functionality
> in embedded or cross-site scenarios.

## Postman Collection

You can import the following comprehensive Postman collection to test all API endpoints:

```json
{
  "info": {
    "name": "Ricardo Auth Provider API v4.0.0",
    "description": "Complete API collection for Ricardo Auth Spring Boot Starter with cookie authentication",
    "version": "4.0.0",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "auth": {
    "type": "noauth"
  },
  "event": [
    {
      "listen": "prerequest",
      "script": {
        "type": "text/javascript",
        "exec": [
          "// Auto-extract CSRF token from cookies if available",
          "const cookies = pm.request.getHeaders()['cookie'] || '';",
          "const csrfMatch = cookies.match(/XSRF-TOKEN=([^;]+)/);",
          "if (csrfMatch) {",
          "    pm.globals.set('csrfToken', decodeURIComponent(csrfMatch[1]));",
          "}"
        ]
      }
    }
  ],
  "item": [
    {
      "name": "Authentication",
      "item": [
        {
          "name": "Login",
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "// Extract cookies from response",
                  "const cookies = pm.response.headers.all()",
                  "    .filter(h => h.key.toLowerCase() === 'set-cookie')",
                  "    .map(h => h.value);",
                  "",
                  "// Store access_token for future requests",
                  "cookies.forEach(cookie => {",
                  "    if (cookie.includes('access_token=')) {",
                  "        const token = cookie.split('access_token=')[1].split(';')[0];",
                  "        pm.globals.set('access_token', token);",
                  "    }",
                  "    if (cookie.includes('refresh_token=')) {",
                  "        const token = cookie.split('refresh_token=')[1].split(';')[0];",
                  "        pm.globals.set('refresh_token', token);",
                  "    }",
                  "    if (cookie.includes('XSRF-TOKEN=')) {",
                  "        const token = cookie.split('XSRF-TOKEN=')[1].split(';')[0];",
                  "        pm.globals.set('csrfToken', decodeURIComponent(token));",
                  "    }",
                  "});",
                  "",
                  "pm.test('Status code is 200', function () {",
                  "    pm.response.to.have.status(200);",
                  "});",
                  "",
                  "pm.test('Access token cookie is set', function () {",
                  "    const hasAccessToken = cookies.some(cookie => cookie.includes('access_token='));",
                  "    pm.expect(hasAccessToken).to.be.true;",
                  "});"
                ]
              }
            }
          ],
          "request": {
            "method": "POST",
            "header": [
              {
                "key": "Content-Type",
                "value": "application/json"
              }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\\n    \\\"email\\\": \\\"{{userEmail}}\\\",\\n    \\\"password\\\": \\\"{{userPassword}}\\\"\\n}"
            },
            "url": {
              "raw": "{{baseUrl}}/api/auth/login",
              "host": ["{{baseUrl}}"],
              "path": ["api", "auth", "login"]
            }
          }
        },
        {
          "name": "Get Current User",
          "event": [
            {
              "listen": "prerequest",
              "script": {
                "exec": [
                  "// Set cookies from stored tokens",
                  "const accessToken = pm.globals.get('access_token');",
                  "const refreshToken = pm.globals.get('refresh_token');",
                  "const csrfToken = pm.globals.get('csrfToken');",
                  "",
                  "if (accessToken) {",
                  "    pm.request.headers.add({",
                  "        key: 'Cookie',",
                  "        value: `access_token=${accessToken}; refresh_token=${refreshToken || ''}; XSRF-TOKEN=${csrfToken || ''}`",
                  "    });",
                  "}"
                ]
              }
            }
          ],
          "request": {
            "method": "GET",
            "header": [],
            "url": {
              "raw": "{{baseUrl}}/api/auth/me",
              "host": ["{{baseUrl}}"],
              "path": ["api", "auth", "me"]
            }
          }
        },
        {
          "name": "Refresh Token",
          "event": [
            {
              "listen": "prerequest",
              "script": {
                "exec": [
                  "const refreshToken = pm.globals.get('refresh_token');",
                  "const csrfToken = pm.globals.get('csrfToken');",
                  "",
                  "if (refreshToken) {",
                  "    pm.request.headers.add({",
                  "        key: 'Cookie',",
                  "        value: `refresh_token=${refreshToken}; XSRF-TOKEN=${csrfToken || ''}`",
                  "    });",
                  "}",
                  "",
                  "if (csrfToken) {",
                  "    pm.request.headers.add({",
                  "        key: 'X-XSRF-TOKEN',",
                  "        value: csrfToken",
                  "    });",
                  "}"
                ]
              }
            }
          ],
          "request": {
            "method": "POST",
            "header": [
              {
                "key": "Content-Type",
                "value": "application/json"
              }
            ],
            "url": {
              "raw": "{{baseUrl}}/api/auth/refresh",
              "host": ["{{baseUrl}}"],
              "path": ["api", "auth", "refresh"]
            }
          }
        },
        {
          "name": "Logout",
          "event": [
            {
              "listen": "prerequest",
              "script": {
                "exec": [
                  "const accessToken = pm.globals.get('access_token');",
                  "const refreshToken = pm.globals.get('refresh_token');",
                  "const csrfToken = pm.globals.get('csrfToken');",
                  "",
                  "if (accessToken) {",
                  "    pm.request.headers.add({",
                  "        key: 'Cookie',",
                  "        value: `access_token=${accessToken}; refresh_token=${refreshToken || ''}; XSRF-TOKEN=${csrfToken || ''}`",
                  "    });",
                  "}",
                  "",
                  "if (csrfToken) {",
                  "    pm.request.headers.add({",
                  "        key: 'X-XSRF-TOKEN',",
                  "        value: csrfToken",
                  "    });",
                  "}"
                ]
              }
            },
            {
              "listen": "test",
              "script": {
                "exec": [
                  "// Clear stored tokens on successful logout",
                  "if (pm.response.code === 200) {",
                  "    pm.globals.clear();",
                  "}"
                ]
              }
            }
          ],
          "request": {
            "method": "POST",
            "header": [],
            "url": {
              "raw": "{{baseUrl}}/api/auth/logout",
              "host": ["{{baseUrl}}"],
              "path": ["api", "auth", "logout"]
            }
          }
        }
      ]
    },
    {
      "name": "Password Reset",
      "item": [
        {
          "name": "Request Password Reset",
          "request": {
            "method": "POST",
            "header": [
              {
                "key": "Content-Type",
                "value": "application/json"
              }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\\n    \\\"email\\\": \\\"{{userEmail}}\\\"\\n}"
            },
            "url": {
              "raw": "{{baseUrl}}/api/auth/reset-request",
              "host": ["{{baseUrl}}"],
              "path": ["api", "auth", "reset-request"]
            }
          }
        },
        {
          "name": "Validate Reset Token",
          "request": {
            "method": "GET",
            "header": [],
            "url": {
              "raw": "{{baseUrl}}/api/auth/reset/{{resetToken}}/validate",
              "host": ["{{baseUrl}}"],
              "path": ["api", "auth", "reset", "{{resetToken}}", "validate"]
            }
          }
        },
        {
          "name": "Complete Password Reset",
          "request": {
            "method": "POST",
            "header": [
              {
                "key": "Content-Type",
                "value": "application/json"
              }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\\n    \\\"password\\\": \\\"{{newPassword}}\\\",\\n    \\\"confirmPassword\\\": \\\"{{newPassword}}\\\"\\n}"
            },
            "url": {
              "raw": "{{baseUrl}}/api/auth/reset/{{resetToken}}",
              "host": ["{{baseUrl}}"],
              "path": ["api", "auth", "reset", "{{resetToken}}"]
            }
          }
        }
      ]
    },
    {
      "name": "User Management",
      "item": [
        {
          "name": "Create User",
          "event": [
            {
              "listen": "prerequest",
              "script": {
                "exec": [
                  "const accessToken = pm.globals.get('access_token');",
                  "const csrfToken = pm.globals.get('csrfToken');",
                  "",
                  "if (accessToken) {",
                  "    pm.request.headers.add({",
                  "        key: 'Cookie',",
                  "        value: `access_token=${accessToken}; XSRF-TOKEN=${csrfToken || ''}`",
                  "    });",
                  "}",
                  "",
                  "if (csrfToken) {",
                  "    pm.request.headers.add({",
                  "        key: 'X-XSRF-TOKEN',",
                  "        value: csrfToken",
                  "    });",
                  "}"
                ]
              }
            }
          ],
          "request": {
            "method": "POST",
            "header": [
              {
                "key": "Content-Type",
                "value": "application/json"
              }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\\n    \\\"username\\\": \\\"{{newUsername}}\\\",\\n    \\\"email\\\": \\\"{{newUserEmail}}\\\",\\n    \\\"password\\\": \\\"{{newUserPassword}}\\\"\\n}"
            },
            "url": {
              "raw": "{{baseUrl}}/api/users/create",
              "host": ["{{baseUrl}}"],
              "path": ["api", "users", "create"]
            }
          }
        },
        {
          "name": "Get User by Username",
          "event": [
            {
              "listen": "prerequest",
              "script": {
                "exec": [
                  "const accessToken = pm.globals.get('access_token');",
                  "",
                  "if (accessToken) {",
                  "    pm.request.headers.add({",
                  "        key: 'Cookie',",
                  "        value: `access_token=${accessToken}`",
                  "    });",
                  "}"
                ]
              }
            }
          ],
          "request": {
            "method": "GET",
            "header": [],
            "url": {
              "raw": "{{baseUrl}}/api/users/{{username}}",
              "host": ["{{baseUrl}}"],
              "path": ["api", "users", "{{username}}"]
            }
          }
        },
        {
          "name": "Get All Users (Admin)",
          "event": [
            {
              "listen": "prerequest",
              "script": {
                "exec": [
                  "const accessToken = pm.globals.get('access_token');",
                  "",
                  "if (accessToken) {",
                  "    pm.request.headers.add({",
                  "        key: 'Cookie',",
                  "        value: `access_token=${accessToken}`",
                  "    });",
                  "}"
                ]
              }
            }
          ],
          "request": {
            "method": "GET",
            "header": [],
            "url": {
              "raw": "{{baseUrl}}/api/users",
              "host": ["{{baseUrl}}"],
              "path": ["api", "users"]
            }
          }
        }
      ]
    },
    {
      "name": "Role Management",
      "item": [
        {
          "name": "Get User Roles",
          "event": [
            {
              "listen": "prerequest",
              "script": {
                "exec": [
                  "const accessToken = pm.globals.get('access_token');",
                  "",
                  "if (accessToken) {",
                  "    pm.request.headers.add({",
                  "        key: 'Cookie',",
                  "        value: `access_token=${accessToken}`",
                  "    });",
                  "}"
                ]
              }
            }
          ],
          "request": {
            "method": "GET",
            "header": [],
            "url": {
              "raw": "{{baseUrl}}/api/users/{{username}}/roles",
              "host": ["{{baseUrl}}"],
              "path": ["api", "users", "{{username}}", "roles"]
            }
          }
        },
        {
          "name": "Add Role to User",
          "event": [
            {
              "listen": "prerequest",
              "script": {
                "exec": [
                  "const accessToken = pm.globals.get('access_token');",
                  "const csrfToken = pm.globals.get('csrfToken');",
                  "",
                  "if (accessToken) {",
                  "    pm.request.headers.add({",
                  "        key: 'Cookie',",
                  "        value: `access_token=${accessToken}; XSRF-TOKEN=${csrfToken || ''}`",
                  "    });",
                  "}",
                  "",
                  "if (csrfToken) {",
                  "    pm.request.headers.add({",
                  "        key: 'X-XSRF-TOKEN',",
                  "        value: csrfToken",
                  "    });",
                  "}"
                ]
              }
            }
          ],
          "request": {
            "method": "POST",
            "header": [
              {
                "key": "Content-Type",
                "value": "application/json"
              }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\\n    \\\"roleName\\\": \\\"{{roleName}}\\\",\\n    \\\"reason\\\": \\\"{{roleReason}}\\\"\\n}"
            },
            "url": {
              "raw": "{{baseUrl}}/api/users/{{username}}/roles",
              "host": ["{{baseUrl}}"],
              "path": ["api", "users", "{{username}}", "roles"]
            }
          }
        },
        {
          "name": "Remove Role from User",
          "event": [
            {
              "listen": "prerequest",
              "script": {
                "exec": [
                  "const accessToken = pm.globals.get('access_token');",
                  "const csrfToken = pm.globals.get('csrfToken');",
                  "",
                  "if (accessToken) {",
                  "    pm.request.headers.add({",
                  "        key: 'Cookie',",
                  "        value: `access_token=${accessToken}; XSRF-TOKEN=${csrfToken || ''}`",
                  "    });",
                  "}",
                  "",
                  "if (csrfToken) {",
                  "    pm.request.headers.add({",
                  "        key: 'X-XSRF-TOKEN',",
                  "        value: csrfToken",
                  "    });",
                  "}"
                ]
              }
            }
          ],
          "request": {
            "method": "DELETE",
            "header": [
              {
                "key": "Content-Type",
                "value": "application/json"
              }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\\n    \\\"roleName\\\": \\\"{{roleName}}\\\",\\n    \\\"reason\\\": \\\"{{roleReason}}\\\"\\n}"
            },
            "url": {
              "raw": "{{baseUrl}}/api/users/{{username}}/roles",
              "host": ["{{baseUrl}}"],
              "path": ["api", "users", "{{username}}", "roles"]
            }
          }
        },
        {
          "name": "Bulk Update User Roles",
          "event": [
            {
              "listen": "prerequest",
              "script": {
                "exec": [
                  "const accessToken = pm.globals.get('access_token');",
                  "const csrfToken = pm.globals.get('csrfToken');",
                  "",
                  "if (accessToken) {",
                  "    pm.request.headers.add({",
                  "        key: 'Cookie',",
                  "        value: `access_token=${accessToken}; XSRF-TOKEN=${csrfToken || ''}`",
                  "    });",
                  "}",
                  "",
                  "if (csrfToken) {",
                  "    pm.request.headers.add({",
                  "        key: 'X-XSRF-TOKEN',",
                  "        value: csrfToken",
                  "    });",
                  "}"
                ]
              }
            }
          ],
          "request": {
            "method": "PUT",
            "header": [
              {
                "key": "Content-Type",
                "value": "application/json"
              }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\\n    \\\"rolesToAdd\\\": [\\\"MODERATOR\\\", \\\"PREMIUM\\\"],\\n    \\\"rolesToRemove\\\": [\\\"BASIC\\\"],\\n    \\\"reason\\\": \\\"User promotion and upgrade\\\"\\n}"
            },
            "url": {
              "raw": "{{baseUrl}}/api/users/{{username}}/roles/bulk",
              "host": ["{{baseUrl}}"],
              "path": ["api", "users", "{{username}}", "roles", "bulk"]
            }
          }
        }
      ]
    }
  ],
  "variable": [
    {
      "key": "baseUrl",
      "value": "http://localhost:8080",
      "type": "string"
    },
    {
      "key": "userEmail",
      "value": "admin@example.com",
      "type": "string"
    },
    {
      "key": "userPassword",
      "value": "AdminPass123!",
      "type": "string"
    },
    {
      "key": "newUsername",
      "value": "johndoe",
      "type": "string"
    },
    {
      "key": "newUserEmail",
      "value": "john@example.com",
      "type": "string"
    },
    {
      "key": "newUserPassword",
      "value": "SecurePass123!",
      "type": "string"
    },
    {
      "key": "username",
      "value": "johndoe",
      "type": "string"
    },
    {
      "key": "roleName",
      "value": "MODERATOR",
      "type": "string"
    },
    {
      "key": "roleReason",
      "value": "User promotion for excellent community management",
      "type": "string"
    },
    {
      "key": "resetToken",
      "value": "your-reset-token-here",
      "type": "string"
    },
    {
      "key": "newPassword",
      "value": "NewSecurePass123!",
      "type": "string"
    }
  ]
}
```

### Postman Setup Instructions

1. **Import Collection**: Copy the JSON above and import it into Postman
2. **Environment Setup**: The collection includes all necessary variables
3. **Update Variables**: 
   - Set `baseUrl` to your server URL (default: `http://localhost:8080`)
   - Update `userEmail` and `userPassword` with valid credentials
4. **Login First**: Always run the "Login" request first to authenticate
5. **Automatic Cookie Handling**: The collection automatically handles cookies and CSRF tokens
6. **Admin Operations**: Role management requires admin credentials

### Key Features

- **Automatic Cookie Management**: Cookies are automatically extracted and stored from login
- **CSRF Token Handling**: CSRF tokens are automatically extracted and included in requests
- **Environment Variables**: All requests use configurable variables
- **Pre-request Scripts**: Automatic cookie and CSRF token injection
- **Test Scripts**: Automatic response validation and token extraction

## SDK Examples

### JavaScript/Node.js (with cookies)

```javascript
// Use fetch with credentials to send cookies
fetch('/api/auth/me', {
    credentials: 'include'
});
```

### Python (with cookies)

```python
import requests

s = requests.Session()
s.post('http://localhost:8080/api/auth/login', json={...})
# Cookies are now stored in the session
r = s.get('http://localhost:8080/api/auth/me')
```
