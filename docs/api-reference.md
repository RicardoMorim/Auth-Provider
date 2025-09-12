# API Reference

Complete API reference for the Ricardo Auth Spring Boot Starter endpoints.

## ⚠️ Breaking Changes in v4.0.0

**Cookie-Only Authentication System**
- **BREAKING**: Authentication now exclusively uses secure HTTP-only cookies
- **No Authorization Headers**: All `Authorization: Bearer` authentication removed
- **HTTPS Required**: Secure cookies require HTTPS in production environments
- **CORS Configuration**: Frontend applications must configure CORS with credentials support

**New Security Features**
- **Enhanced CORS**: Comprehensive CORS configuration with credentials support
- **Password Reset**: OWASP-compliant password reset with email integration
- **Role Management**: Full CRUD API for role management with proper authorization
- **OpenAPI Integration**: Complete Swagger/OpenAPI documentation at `/swagger-ui.html`
- **Domain Events**: Comprehensive audit trail with event publishing
- **Enhanced Security**: Advanced input validation, sanitization, and security headers

**API Changes**
- All endpoints now use cookie-based authentication exclusively
- New password reset endpoints: `/api/auth/password-reset/*`
- New role management endpoints: `/api/roles/*`
- Enhanced user management with improved validation
- Complete OpenAPI documentation with interactive testing

## Base URL

All endpoints are relative to your application's base URL:

```
http://localhost:8080  # Development
https://yourdomain.com # Production
```

## Authentication

All endpoints require authentication via secure HTTP-only cookies (`access_token`, `refresh_token`). 

**Key Authentication Features:**
- **Cookie-Only**: All authentication uses secure HTTP-only cookies exclusively
- **No Authorization Headers**: Authorization header authentication has been completely removed
- **HTTPS Required**: Secure cookies require HTTPS in production environments
- **CORS Support**: Comprehensive CORS configuration with credentials support
- **Interactive Documentation**: Complete OpenAPI documentation available at `/swagger-ui.html`

### Frontend Integration Requirements

**CORS Configuration Required:**
```yaml
ricardo:
  auth:
    cors:
      allowed-origins: ["http://localhost:3000", "https://yourdomain.com"]
      allow-credentials: true
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
| POST | `/api/auth/revoke` | Revoke tokens (ADMIN) | Cookies | Yes |
| POST | `/api/auth/password-reset/request` | Request password reset | No | No |
| POST | `/api/auth/password-reset/confirm` | Confirm password reset | No | No |
| GET | `/api/auth/me` | Get current user info | Cookies | No |

### User Management Endpoints

| Method | Endpoint | Description | Auth Required | CSRF |
|--------|----------|-------------|---------------|------|
| POST | `/api/users/create` | Create new user | No | No |
| GET | `/api/users/{id}` | Get user by ID | Cookies | No |
| GET | `/api/users/email/{email}` | Get user by email | Cookies | No |
| GET | `/api/users/exists/{email}` | Check if user exists | Cookies | No |
| PUT | `/api/users/update/{id}` | Update user | Cookies | Yes |
| DELETE | `/api/users/delete/{id}` | Delete user | Cookies | Yes |

### Role Management Endpoints (ADMIN Only)

| Method | Endpoint | Description | Auth Required | CSRF |
|--------|----------|-------------|---------------|------|
| GET | `/api/roles` | List all roles | Cookies (ADMIN) | No |
| POST | `/api/roles` | Create new role | Cookies (ADMIN) | Yes |
| PUT | `/api/roles/{id}` | Update role | Cookies (ADMIN) | Yes |
| DELETE | `/api/roles/{id}` | Delete role | Cookies (ADMIN) | Yes |

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

### POST /api/auth/password-reset/request

Request a password reset via email. Sends a secure reset token to the user's email address.

#### Request

**Headers:**

```
Content-Type: application/json
```

**Body:**

```json
{
  "email": "string"
}
```

#### Response

**Success (200 OK):**

```json
{
  "message": "Password reset email sent successfully"
}
```

**Error (400 Bad Request) - Invalid Email:**

```json
{
  "error": "Bad Request",
  "message": "Invalid email format",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/auth/password-reset/request"
}
```

**Error (404 Not Found) - User Not Found:**

```json
{
  "error": "Not Found",
  "message": "User not found with email: user@example.com",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/auth/password-reset/request"
}
```

**Error (429 Too Many Requests) - Rate Limited:**

```json
{
  "error": "Too Many Requests",
  "message": "Too many password reset attempts. Please try again later.",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/auth/password-reset/request"
}
```

#### Example

```bash
curl -X POST http://localhost:8080/api/auth/password-reset/request \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

### POST /api/auth/password-reset/confirm

Confirm password reset using the token received via email and set a new password.

#### Request

**Headers:**

```
Content-Type: application/json
```

**Body:**

```json
{
  "token": "string",
  "newPassword": "string"
}
```

#### Response

**Success (200 OK):**

```json
{
  "message": "Password reset successfully"
}
```

**Error (400 Bad Request) - Invalid Token:**

```json
{
  "error": "Bad Request",
  "message": "Invalid or expired reset token",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/auth/password-reset/confirm"
}
```

**Error (400 Bad Request) - Password Policy Violation:**

```json
{
  "error": "Bad Request",
  "message": "Password must contain at least one uppercase letter",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/auth/password-reset/confirm"
}
```

#### Example

```bash
curl -X POST http://localhost:8080/api/auth/password-reset/confirm \
  -H "Content-Type: application/json" \
  -d '{
    "token": "reset-token-from-email",
    "newPassword": "NewSecurePass@123!"
  }'
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

### GET /api/roles

Get all available roles in the system.

#### Request

**Headers:**

```
Cookie: access_token=YOUR_ACCESS_TOKEN_HERE;
```

#### Response

**Success (200 OK):**

```json
[
  {
    "id": 1,
    "name": "ROLE_USER",
    "description": "Standard user role with basic permissions"
  },
  {
    "id": 2,
    "name": "ROLE_ADMIN",
    "description": "Administrator role with full system access"
  },
  {
    "id": 3,
    "name": "ROLE_MODERATOR",
    "description": "Moderator role with limited admin privileges"
  }
]
```

#### Example

```bash
curl -X GET http://localhost:8080/api/roles \
  --cookie "access_token=YOUR_ADMIN_ACCESS_TOKEN_HERE"
```

### POST /api/roles (ADMIN only)

Create a new role in the system.

#### Request

**Headers:**

```
Content-Type: application/json
Cookie: access_token=YOUR_ACCESS_TOKEN_HERE;
```

**Body:**

```json
{
  "name": "string",
  "description": "string"
}
```

#### Response

**Success (201 Created):**

```json
{
  "id": 4,
  "name": "ROLE_MODERATOR",
  "description": "Moderator role with limited admin privileges"
}
```

**Error (400 Bad Request) - Role Already Exists:**

```json
{
  "error": "Bad Request",
  "message": "Role with name ROLE_MODERATOR already exists",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/roles"
}
```

**Error (403 Forbidden) - Insufficient Permissions:**

```json
{
  "error": "Forbidden",
  "message": "Access denied: ADMIN role required",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/roles"
}
```

#### Example

```bash
curl -X POST http://localhost:8080/api/roles \
  --cookie "access_token=YOUR_ADMIN_ACCESS_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ROLE_MODERATOR",
    "description": "Moderator role with limited admin privileges"
  }'
```

### PUT /api/roles/{id} (ADMIN only)

Update an existing role.

#### Request

**Headers:**

```
Content-Type: application/json
Cookie: access_token=YOUR_ACCESS_TOKEN_HERE;
```

**Path Parameters:**

- `id` (Long): Role ID to update

**Body:**

```json
{
  "name": "string",
  "description": "string"
}
```

#### Response

**Success (200 OK):**

```json
{
  "id": 3,
  "name": "ROLE_MODERATOR",
  "description": "Updated moderator role with enhanced privileges"
}
```

**Error (404 Not Found):**

```json
{
  "error": "Not Found",
  "message": "Role not found with id: 999",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/roles/999"
}
```

#### Example

```bash
curl -X PUT http://localhost:8080/api/roles/3 \
  --cookie "access_token=YOUR_ADMIN_ACCESS_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ROLE_MODERATOR",
    "description": "Updated moderator role with enhanced privileges"
  }'
```

### DELETE /api/roles/{id} (ADMIN only)

Delete a role from the system. The role cannot be deleted if it's assigned to any users.

#### Request

**Headers:**

```
Cookie: access_token=YOUR_ACCESS_TOKEN_HERE;
```

**Path Parameters:**

- `id` (Long): Role ID to delete

#### Response

**Success (204 No Content):**

```
(Empty response body)
```

**Error (400 Bad Request) - Role Still in Use:**

```json
{
  "error": "Bad Request",
  "message": "Cannot delete role: Role is assigned to 5 users",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/roles/3"
}
```

**Error (403 Forbidden) - Cannot Delete System Roles:**

```json
{
  "error": "Forbidden",
  "message": "Cannot delete system role: ROLE_USER",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/roles/1"
}
```

#### Example

```bash
curl -X DELETE http://localhost:8080/api/roles/4 \
  --cookie "access_token=YOUR_ADMIN_ACCESS_TOKEN_HERE"
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

You can import the following Postman collection to test the API:

```json
{
  "info": {
    "name": "Ricardo Auth API",
    "description": "API collection for Ricardo Auth Spring Boot Starter"
  },
  "item": [
    {
      "name": "Login",
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
          "raw": "{\n    \"email\": \"user@example.com\",\n    \"password\": \"password\"\n}"
        },
        "url": {
          "raw": "{{baseUrl}}/api/auth/login",
          "host": [
            "{{baseUrl}}"
          ],
          "path": [
            "api",
            "auth",
            "login"
          ]
        }
      }
    },
    {
      "name": "Get Current User",
      "request": {
        "method": "GET",
        "header": [],
        "url": {
          "raw": "{{baseUrl}}/api/auth/me",
          "host": [
            "{{baseUrl}}"
          ],
          "path": [
            "api",
            "auth",
            "me"
          ]
        }
      },
      "cookie": [
        {
          "key": "access_token",
          "value": "{{token}}"
        }
      ]
    },
    {
      "name": "Create User",
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
          "raw": "{\n    \"username\": \"johndoe\",\n    \"email\": \"john@example.com\",\n    \"password\": \"securepassword123\"\n}"
        },
        "url": {
          "raw": "{{baseUrl}}/api/users/create",
          "host": [
            "{{baseUrl}}"
          ],
          "path": [
            "api",
            "users",
            "create"
          ]
        }
      }
    }
  ],
  "variable": [
    {
      "key": "baseUrl",
      "value": "http://localhost:8080"
    },
    {
      "key": "token",
      "value": ""
    }
  ]
}
```

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
