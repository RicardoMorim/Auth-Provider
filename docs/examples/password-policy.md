# Password Policy Examples

**Perfect for:** Understanding and implementing password policies  
**Complexity:** ⭐ Easy  
**Time:** 10 minutes  
**New in:** v1.1.0 🆕

## What You'll Learn

How to configure and use Ricardo Auth's comprehensive password policy system:

- ✅ Configure password strength requirements
- ✅ Set up environment-specific policies
- ✅ Handle password validation errors
- ✅ Implement custom password rules
- ✅ Test password policies effectively

## Quick Start

### Basic Password Policy Configuration

```yaml
# application.yml
ricardo:
  auth:
    password-policy:
      min-length: 10                    # Minimum password length
      max-length: 128                   # Maximum password length
      require-uppercase: true           # Must contain A-Z
      require-lowercase: true           # Must contain a-z
      require-digits: true              # Must contain 0-9
      require-special-chars: true       # Must contain symbols
      special-characters: "!@#$%^&*()"  # Allowed special characters
      prevent-common-passwords: true    # Block weak passwords
```

**Example valid password:** `MySecure@Pass123!`

## Configuration Examples

### 1. Development Environment (Relaxed)

**Use case:** Quick testing and development

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 6                     # Shorter for testing
      require-uppercase: false          # Not required
      require-lowercase: true           # Required
      require-digits: true              # Required
      require-special-chars: false      # Not required for testing
      prevent-common-passwords: false   # Allow weak passwords
```

**Valid passwords:** `test123`, `dev123`, `simple1`

### 2. Standard Business Application

**Use case:** Most business applications

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 8                     # Standard length
      require-uppercase: true           # A-Z required
      require-lowercase: true           # a-z required
      require-digits: true              # 0-9 required
      require-special-chars: true       # Symbols required
      special-characters: "!@#$%^&*()_+-=[]{}|;:,.<>?"
      prevent-common-passwords: true    # Block common passwords
```

**Valid passwords:** `Business@123`, `SecurePass1!`, `MyApp$2024`

### 3. High-Security Environment

**Use case:** Financial, healthcare, government applications

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 15                    # Long passwords
      max-length: 64                    # Reasonable maximum
      require-uppercase: true           # A-Z required
      require-lowercase: true           # a-z required
      require-digits: true              # 0-9 required
      require-special-chars: true       # Symbols required
      special-characters: "!@#$%^&*()_+-=[]{}|;:,.<>?"
      prevent-common-passwords: true    # Block common passwords
```

**Valid passwords:** `MyVerySecure@Password123!`, `HighSecurity$App2024#`

### 4. Mobile-Friendly Configuration

**Use case:** Mobile applications with software keyboards

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 8                     # Standard length
      require-uppercase: true           # A-Z required
      require-lowercase: true           # a-z required
      require-digits: true              # 0-9 required
      require-special-chars: false      # Relaxed for mobile keyboards
      prevent-common-passwords: true    # Still block weak passwords
```

**Valid passwords:** `MobileApp123`, `MyPhone2024`, `SecureLogin99`

## Environment-Specific Configuration

### Using Spring Profiles

#### application.yml (base configuration)

```yaml
ricardo:
  auth:
    password-policy:
      # Default settings
      min-length: 8
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      prevent-common-passwords: true

---
# Development profile
spring:
  config:
    activate:
      on-profile: dev

ricardo:
  auth:
    password-policy:
      min-length: 6                     # Relaxed for development
      require-special-chars: false      # Easier testing
      prevent-common-passwords: false   # Allow weak passwords

---
# Production profile
spring:
  config:
    activate:
      on-profile: prod

ricardo:
  auth:
    password-policy:
      min-length: 12                    # Stricter for production
      max-length: 128
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      prevent-common-passwords: true
```

### Using Environment Variables

```bash
# Development
export RICARDO_AUTH_PASSWORD_POLICY_MIN_LENGTH=6
export RICARDO_AUTH_PASSWORD_POLICY_REQUIRE_SPECIAL_CHARS=false

# Production
export RICARDO_AUTH_PASSWORD_POLICY_MIN_LENGTH=12
export RICARDO_AUTH_PASSWORD_POLICY_REQUIRE_SPECIAL_CHARS=true
export RICARDO_AUTH_PASSWORD_POLICY_PREVENT_COMMON_PASSWORDS=true
```

#### application.yml with environment variables

```yaml
ricardo:
  auth:
    password-policy:
      min-length: ${RICARDO_AUTH_PASSWORD_POLICY_MIN_LENGTH:8}
      require-uppercase: ${RICARDO_AUTH_PASSWORD_POLICY_REQUIRE_UPPERCASE:true}
      require-lowercase: ${RICARDO_AUTH_PASSWORD_POLICY_REQUIRE_LOWERCASE:true}
      require-digits: ${RICARDO_AUTH_PASSWORD_POLICY_REQUIRE_DIGITS:true}
      require-special-chars: ${RICARDO_AUTH_PASSWORD_POLICY_REQUIRE_SPECIAL_CHARS:true}
      prevent-common-passwords: ${RICARDO_AUTH_PASSWORD_POLICY_PREVENT_COMMON_PASSWORDS:true}
```

## Error Handling Examples

### Common Password Policy Errors

#### 1. Password Too Short

```json
{
  "error": "Bad Request",
  "message": "Password must be at least 8 characters long",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Fix:** Use a longer password

```bash
# ❌ Too short
curl -X POST http://localhost:8080/api/users/create \
  -d '{"password": "abc123"}'

# ✅ Correct length
curl -X POST http://localhost:8080/api/users/create \
  -d '{"password": "MySecure@Pass123!"}'
```

#### 2. Missing Character Types

```json
{
  "error": "Bad Request",
  "message": "Password must contain at least one uppercase letter",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Fix:** Add required character types

```bash
# ❌ No uppercase
curl -X POST http://localhost:8080/api/users/create \
  -d '{"password": "mysecure@pass123!"}'

# ✅ Has uppercase
curl -X POST http://localhost:8080/api/users/create \
  -d '{"password": "MySecure@Pass123!"}'
```

#### 3. Common Password Detected

```json
{
  "error": "Bad Request",
  "message": "Password is too common and easily guessable",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Fix:** Use a unique password

```bash
# ❌ Common password
curl -X POST http://localhost:8080/api/users/create \
  -d '{"password": "Password123!"}'

# ✅ Unique password
curl -X POST http://localhost:8080/api/users/create \
  -d '{"password": "MyUniqueApp@2024!"}'
```

### Frontend Error Handling

#### JavaScript Example

```javascript
async function registerUser(username, email, password) {
    try {
        const response = await fetch('/api/users/create', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({username, email, password}),
        });

        if (!response.ok) {
            const error = await response.json();

            // Handle specific password policy errors
            if (error.message.includes('Password must')) {
                showPasswordPolicyError(error.message);
                return {success: false, error: 'password_policy'};
            }

            return {success: false, error: error.message};
        }

        const user = await response.json();
        return {success: true, user};

    } catch (error) {
        return {success: false, error: 'Network error'};
    }
}

function showPasswordPolicyError(message) {
    const errorDiv = document.getElementById('password-error');
    errorDiv.innerHTML = `
        <div class="alert alert-warning">
            <strong>Password Requirements:</strong><br>
            ${message}<br><br>
            <small>
                Password must:
                <ul>
                    <li>Be at least 8 characters long</li>
                    <li>Contain uppercase letters (A-Z)</li>
                    <li>Contain lowercase letters (a-z)</li>
                    <li>Contain digits (0-9)</li>
                    <li>Contain special characters (!@#$%^&*)</li>
                    <li>Not be a common password</li>
                </ul>
            </small>
        </div>
    `;
}
```

## Testing Password Policies

### 1. Test Script for Different Passwords

```bash
#!/bin/bash

BASE_URL="http://localhost:8080"

echo "Testing Password Policy..."

# Test cases
declare -a test_cases=(
    "weak123:Too short and weak"
    "PASSWORD123:No lowercase or special chars"
    "password123:No uppercase or special chars"  
    "Password:No digits or special chars"
    "Password123:No special characters"
    "password123!:No uppercase"
    "PASSWORD123!:No lowercase"
    "MySecure@Pass123!:Should be valid"
    "password:Common password"
    "123456789:Common password"
)

# Test each password
for test_case in "${test_cases[@]}"; do
    IFS=':' read -r password description <<< "$test_case"
    
    echo "Testing: $password ($description)"
    
    response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/api/users/create" \
        -H "Content-Type: application/json" \
        -d "{
            \"username\": \"testuser$(date +%s)\",
            \"email\": \"test$(date +%s)@example.com\",
            \"password\": \"$password\"
        }")
    
    http_code="${response: -3}"
    body="${response%???}"
    
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        echo "✅ PASSED: $description"
    else
        echo "❌ FAILED: $description"
        echo "   Response: $body"
    fi
    echo ""
done
```

### 2. Unit Test Example

```java

@Test
public void testPasswordPolicyValidation() {
    // Test too short password
    assertThatThrownBy(() -> {
        userService.createUser("test", "test@example.com", "short");
    }).isInstanceOf(PasswordPolicyException.class)
            .hasMessageContaining("must be at least");

    // Test missing uppercase
    assertThatThrownBy(() -> {
        userService.createUser("test", "test@example.com", "lowercase123!");
    }).isInstanceOf(PasswordPolicyException.class)
            .hasMessageContaining("uppercase letter");

    // Test valid password
    assertThatCode(() -> {
        userService.createUser("test", "test@example.com", "ValidPass123!");
    }).doesNotThrowAnyException();
}
```

## Custom Password Validation

### Adding Custom Rules

While Ricardo Auth provides comprehensive built-in validation, you can extend it:

```java

@Component
public class CustomPasswordValidator {

    @Autowired
    private PasswordPolicyService passwordPolicyService;

    public void validateCustomRules(String password) {
        // Use built-in validation first
        passwordPolicyService.validatePassword(password);

        // Add custom rules
        if (password.contains("company")) {
            throw new PasswordPolicyException("Password cannot contain company name");
        }

        if (password.matches(".*([a-zA-Z])\\1{2,}.*")) {
            throw new PasswordPolicyException("Password cannot have more than 2 consecutive identical characters");
        }

        // Check against custom dictionary
        if (isInCustomBlacklist(password)) {
            throw new PasswordPolicyException("Password is not allowed");
        }
    }

    private boolean isInCustomBlacklist(String password) {
        // Implement custom blacklist check
        Set<String> customBlacklist = Set.of(
                "companyname123",
                "organization2024",
                "department123"
        );
        return customBlacklist.contains(password.toLowerCase());
    }
}
```

## Password Policy Best Practices

### 1. Security Guidelines

```yaml
# ✅ Recommended for most applications
ricardo:
  auth:
    password-policy:
      min-length: 10                    # Good balance of security and usability
      require-uppercase: true           # Increases entropy
      require-lowercase: true           # Standard requirement
      require-digits: true              # Prevents all-letter passwords
      require-special-chars: true       # Significantly increases security
      prevent-common-passwords: true    # Essential security feature
```

### 2. User Experience Guidelines

```yaml
# ✅ User-friendly configuration
ricardo:
  auth:
    password-policy:
      min-length: 8                     # Not too long for mobile
      max-length: 128                   # Reasonable upper limit
      special-characters: "!@#$%^&*()_+-=[]{}|;:,.<>?"  # Common keyboard symbols
```

### 3. Progressive Enhancement

Start with basic requirements and increase security over time:

```yaml
# Phase 1: Basic requirements
ricardo:
  auth:
    password-policy:
      min-length: 8
      require-digits: true

# Phase 2: Add character requirements  
ricardo:
  auth:
    password-policy:
      min-length: 8
      require-uppercase: true
      require-lowercase: true
      require-digits: true

# Phase 3: Full security
ricardo:
  auth:
    password-policy:
      min-length: 10
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      prevent-common-passwords: true
```

## Common Use Cases

### 1. SaaS Application

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 8
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      prevent-common-passwords: true
```

### 2. Internal Corporate Application

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 12
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      prevent-common-passwords: true
```

### 3. Consumer Mobile App

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 8
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: false      # Easier for mobile keyboards
      prevent-common-passwords: true
```

### 4. Educational Platform

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 6                     # Shorter for students
      require-uppercase: false          # Simpler requirements
      require-lowercase: true
      require-digits: true
      require-special-chars: false
      prevent-common-passwords: true
```

## ⚠️ Breaking Changes in v3.0.0

- **UUID Primary Keys:** All user IDs are now UUID instead of Long
- **Enhanced Decoupling:** New factory pattern for user creation
- **Repository Types:** Choose between JPA and PostgreSQL implementations
- **CSRF Protection:** Cross-Site Request Forgery protection now enabled by default (NEW)

## ⚠️ Breaking Changes in v2.0.0

- **Token cookies**: Authentication now uses secure cookies for access and refresh tokens, with `httpOnly`, `secure`,
  and `sameSite` flags by default. Update your frontend to use cookies for authentication.
- **HTTPS enforcement**: By default, the API only allows HTTPS. To disable, set `ricardo.auth.redirect-https=false`.
- **Blocklist support**: Add `ricardo.auth.token-blocklist` config to enable in-memory or Redis-based token revocation.
- **Rate limiting**: Add `ricardo.auth.rate-limiter` config for in-memory or Redis-based rate limiting.
- **/api/auth/revoke endpoint**: New admin-only endpoint to revoke any access or refresh token.

---

## Example: Full Security with Blocklist and Rate Limiting

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 10
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      prevent-common-passwords: true
    token-blocklist:
      enabled: true
      type: redis   # or 'memory' for dev
    rate-limiter:
      enabled: true
      type: redis   # or 'memory' for dev
      max-requests: 100
      time-window-ms: 60000
    cookies:
      access:
        secure: true
        httpOnly: true
        sameSite: Strict
        path: /
      refresh:
        secure: true
        httpOnly: true
        sameSite: Strict
        path: /api/auth/refresh
    redirect-https: true
```

## Token Revocation (Admin Only)

A new admin-only endpoint allows you to revoke any access or refresh token:

```http
POST /api/auth/revoke
Authorization: Bearer <admin-access-token>
Content-Type: application/json

"<token-to-revoke>"
```

- Works for both access and refresh tokens.
- Revoked tokens are blocked in memory or Redis (depending on config).

## Cookie-based Authentication

- All authentication now uses cookies for access and refresh tokens.
- Cookies are set with `httpOnly`, `secure`, and `sameSite` flags for security.
- Most endpoints do not accept Authorization headers anymore (except /revoke).

---

🔒 **Secure passwords are the foundation of application security!** Use these examples to implement the right policy for
your needs.
