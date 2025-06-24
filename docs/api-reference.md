# API Reference

Complete API reference for the Ricardo Auth Spring Boot Starter endpoints.

## Base URL

All endpoints are relative to your application's base URL:
```
http://localhost:8080  # Development
https://yourdomain.com # Production
```

## Authentication

Most endpoints require authentication via JWT token in the Authorization header:
```
Authorization: Bearer <your-jwt-token>
```

## Authentication Endpoints

### POST /api/auth/login

Authenticate a user and receive a JWT token.

#### Request

**Headers:**
```
Content-Type: application/json
```

**Body:**
```json
{
    "email": "string",     // Required: User's email address
    "password": "string"   // Required: User's password
}
```

#### Response

**Success (200 OK):**
```json
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyNDI2MjJ9.signature"
}
```

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

### GET /api/auth/me

Get information about the currently authenticated user.

#### Request

**Headers:**
```
Authorization: Bearer <token>
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
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## User Management Endpoints

### POST /api/users/create

Create a new user account.

#### Request

**Headers:**
```
Content-Type: application/json
```

**Body:**
```json
{
    "username": "string",  // Required: Unique username
    "email": "string",     // Required: Valid email address (unique)
    "password": "string"   // Required: Password (will be encrypted)
}
```

#### Response

**Success (201 Created):**
```json
{
    "id": 1,
    "username": "johndoe",
    "email": "john@example.com"
}
```

**Error (400 Bad Request):**
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
    "password": "securepassword123"
  }'
```

### GET /api/users/{id}

Get user information by ID.

#### Request

**Headers:**
```
Authorization: Bearer <token>
```

**Path Parameters:**
- `id` (number): User ID

#### Response

**Success (200 OK):**
```json
{
    "id": 1,
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
curl -X GET http://localhost:8080/api/users/1 \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### GET /api/users/email/{email}

Get user information by email address.

#### Request

**Headers:**
```
Authorization: Bearer <token>
```

**Path Parameters:**
- `email` (string): User email address

#### Response

**Success (200 OK):**
```json
{
    "id": 1,
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
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
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
Authorization: Bearer <token>
Content-Type: application/json
```

**Path Parameters:**
- `id` (number): User ID to update

**Body:**
```json
{
    "username": "string",  // Optional: New username
    "email": "string",     // Optional: New email
    "password": "string"   // Optional: New password
}
```

#### Response

**Success (200 OK):**
```json
{
    "id": 1,
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
curl -X PUT http://localhost:8080/api/users/update/1 \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
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
Authorization: Bearer <token>
```

**Path Parameters:**
- `id` (number): User ID to delete

#### Response

**Success (204 No Content):**
```
(Empty response body)
```

**Error (404 Not Found):**
```json
{
    "error": "Not Found",
    "message": "User not found with id: 999",
    "timestamp": "2024-01-15T10:30:00Z",
    "path": "/api/users/delete/999"
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
curl -X DELETE http://localhost:8080/api/users/delete/1 \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## Error Responses

### Common Error Formats

All error responses follow this structure:

```json
{
    "error": "string",      // HTTP status text
    "message": "string",    // Detailed error message
    "timestamp": "string",  // ISO 8601 timestamp
    "path": "string"        // Request path that caused the error
}
```

### HTTP Status Codes

| Status Code | Description | Common Causes |
|-------------|-------------|---------------|
| 200 | OK | Successful GET requests |
| 201 | Created | Successful POST requests |
| 204 | No Content | Successful DELETE requests |
| 400 | Bad Request | Invalid request data, validation errors |
| 401 | Unauthorized | Missing or invalid JWT token, wrong credentials |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource doesn't exist |
| 409 | Conflict | Resource already exists (username/email taken) |
| 500 | Internal Server Error | Server-side errors |

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

The API may implement rate limiting. When rate limited, you'll receive:

**Response (429 Too Many Requests):**
```json
{
    "error": "Too Many Requests",
    "message": "Rate limit exceeded. Try again in 60 seconds.",
    "timestamp": "2024-01-15T10:30:00Z",
    "retryAfter": 60
}
```

## JWT Token Format

JWT tokens contain the following claims:

```json
{
    "sub": "user@example.com",     // Subject (username/email)
    "iat": 1516239022,             // Issued at (timestamp)
    "exp": 1516843822,             // Expiration (timestamp)
    "authorities": ["ROLE_USER"]   // User roles/authorities
}
```

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
                    "host": ["{{baseUrl}}"],
                    "path": ["api", "auth", "login"]
                }
            }
        },
        {
            "name": "Get Current User",
            "request": {
                "method": "GET",
                "header": [
                    {
                        "key": "Authorization",
                        "value": "Bearer {{token}}"
                    }
                ],
                "url": {
                    "raw": "{{baseUrl}}/api/auth/me",
                    "host": ["{{baseUrl}}"],
                    "path": ["api", "auth", "me"]
                }
            }
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
                    "host": ["{{baseUrl}}"],
                    "path": ["api", "users", "create"]
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

### JavaScript/Node.js

```javascript
class AuthClient {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
        this.token = null;
    }

    async login(email, password) {
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
            return data;
        }
        throw new Error('Login failed');
    }

    async getCurrentUser() {
        const response = await fetch(`${this.baseUrl}/api/auth/me`, {
            headers: {
                'Authorization': `Bearer ${this.token}`
            }
        });
        
        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to get current user');
    }
}
```

### Python

```python
import requests

class AuthClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.token = None

    def login(self, email, password):
        response = requests.post(
            f"{self.base_url}/api/auth/login",
            json={"email": email, "password": password}
        )
        response.raise_for_status()
        data = response.json()
        self.token = data["token"]
        return data

    def get_current_user(self):
        response = requests.get(
            f"{self.base_url}/api/auth/me",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        response.raise_for_status()
        return response.json()
```
