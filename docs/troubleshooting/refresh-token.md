# Refresh Token Troubleshooting

Common issues and solutions for refresh token functionality after v2.0.0.

## 🚨 Breaking Changes in v2.0.0

- **Blocklist:** Both refresh and access tokens can be revoked instantly (logout, admin, endpoint).
- **Rate limiting:** Protection against abuse, with in-memory or Redis implementation.
- **Secure cookies:** Tokens are now sent via `HttpOnly`, `Secure`, `SameSite` cookies by default. HTTPS is required.
- **Token revocation endpoint:** `/api/auth/revoke` (ADMIN) to revoke any token.
- **Automatic cleanup:** Old tokens are removed when user token limit is reached.
- **New properties:** Detailed configuration for cookies, blocklist, rate limiting, HTTPS, etc.

## 🔍 Quick Diagnosis

### Check if Refresh Tokens are Enabled

```yaml
ricardo:
  auth:
    refresh-tokens:
      enabled: true
```

### Test the Refresh Endpoint

```bash
curl -v -X POST https://localhost:8443/api/auth/refresh \
  --cookie "refresh_token=YOUR_REFRESH_TOKEN_HERE"
```

## Common Errors and Solutions

### 1. "Refresh token not found" or "Invalid or expired refresh token"

- Token may have expired, been revoked (blocklist), or already rotated.
- Use the `/api/auth/revoke` endpoint to revoke tokens manually (ADMIN).
- Always use the latest refresh token returned by the backend.

### 2. "Too many refresh tokens" or old tokens not removed

- The system removes old tokens automatically when the per-user limit (`max-tokens-per-user`) is reached.
- Parameter: `cleanup-interval` sets cleanup frequency.

```yaml
ricardo:
  auth:
    refresh-tokens:
      max-tokens-per-user: 5
      cleanup-interval: 3600000  # 1 hour
```

### 3. Rate Limiting (HTTP 429)

- If you receive HTTP 429, check the configuration:

```yaml
ricardo:
  auth:
    rate-limiter:
      enabled: true
      type: memory # or redis
      max-requests: 100
      time-window-ms: 60000
```

### 4. Cookies not working or session not persisting

- Ensure the frontend sends cookies with `credentials: 'include'`.
- Cookies must have `HttpOnly`, `Secure`, `SameSite` flags and only work via HTTPS.

```yaml
ricardo:
  auth:
    cookies:
      access:
        http-only: true
        secure: true
        same-site: Strict
      refresh:
        http-only: true
        secure: true
        same-site: Strict
    redirect-https: true
```

### 5. Token Revocation (Blocklist)

- To revoke a token (access or refresh), use:

```bash
curl -X POST https://localhost:8443/api/auth/revoke \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '"TOKEN_TO_REVOKE"'
```

- Revoked tokens are rejected immediately on all protected routes.

### 6. Debug and Logging

```yaml
logging:
  level:
    com.ricardo.auth: DEBUG
    org.springframework.security: DEBUG
    org.springframework.data.jpa: DEBUG
    org.hibernate.SQL: DEBUG
```

---

This guide covers the main changes and common issues after upgrading to v2.0.0. See also the troubleshooting files for
authentication, CORS, and password policy.
