# Password Policy Configuration

> **Breaking Changes (v3.0.0):**
> - **UUID Primary Keys:** All user IDs are now UUID instead of Long
> - **Enhanced Decoupling:** New factory pattern for user creation
> - **Repository Types:** Choose between JPA and PostgreSQL implementations
>
> **v2.0.0 Changes:**
> - Authentication now uses secure cookies (`access_token`, `refresh_token`) with `HttpOnly`, `Secure`, and `SameSite`
    flags by default. You must use HTTPS in production or set `ricardo.auth.cookies.access.secure: false` for local
    development only.
> - New blocklist and rate limiting features are available (see below).
> - New `/api/auth/revoke` admin endpoint for revoking tokens (access or refresh).

Complete guide to configuring Ricardo Auth's password policy system (v3.0.0+).ord Policy Configuration

> **Breaking Change (v2.0.0):**
> - Authentication now uses secure cookies (`access_token`, `refresh_token`) with `HttpOnly`, `Secure`, and `SameSite`
    flags by default. You must use HTTPS in production or set `ricardo.auth.cookies.access.secure: false` for local
    development only.
> - New blocklist and rate limiting features are available (see below).
> - New `/api/auth/revoke` admin endpoint for revoking tokens (access or refresh).

Complete guide to configuring Ricardo Auth's password policy system (v1.1.0+).

## 🎯 Quick Start

**Use these recommended settings for most applications:**

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 10                  # Strong minimum length
      require-uppercase: true         # Must have A-Z
      require-lowercase: true         # Must have a-z  
      require-digits: true            # Must have 0-9
      require-special-chars: true     # Must have !@#$%^&*
      prevent-common-passwords: true  # Block weak passwords
```

**Example valid password:** `MySecure@Pass123!`

## 📋 Complete Configuration Reference

### All Available Options

```yaml
ricardo:
  auth:
    password-policy:
      # Length requirements
      min-length: 8                     # Minimum characters (default: 8)
      max-length: 128                   # Maximum characters (default: 128)

      # Character type requirements
      require-uppercase: true           # Must contain A-Z (default: true)
      require-lowercase: true           # Must contain a-z (default: true)
      require-digits: true              # Must contain 0-9 (default: true)
      require-special-chars: true       # Must contain symbols (default: true)

      # Special character configuration
      special-characters: "!@#$%^&*()_+-=[]{}|;:,.<>?" # Allowed symbols

      # Security features
      prevent-common-passwords: true    # Block common passwords (default: true)
      common-passwords-file: "/commonpasswords.txt"  # Custom weak password list
```

### Configuration Properties Table

| Property                   | Type    | Default      | Description                       |
|----------------------------|---------|--------------|-----------------------------------|
| `min-length`               | Integer | `8`          | Minimum password length           |
| `max-length`               | Integer | `128`        | Maximum password length           |
| `require-uppercase`        | Boolean | `true`       | Require A-Z characters            |
| `require-lowercase`        | Boolean | `true`       | Require a-z characters            |
| `require-digits`           | Boolean | `true`       | Require 0-9 characters            |
| `require-special-chars`    | Boolean | `true`       | Require special characters        |
| `special-characters`       | String  | `"!@#$%^&*"` | Allowed special characters        |
| `prevent-common-passwords` | Boolean | `true`       | Block common weak passwords       |
| `common-passwords-file`    | String  | `null`       | Path to custom password blacklist |

## 🔧 Environment-Specific Configurations

### Development Environment (Relaxed)

For easier testing and development:

```yaml
# application-dev.yml
spring:
  config:
    activate:
      on-profile: dev

ricardo:
  auth:
    password-policy:
      min-length: 6                     # Shorter for testing
      require-uppercase: false          # Relaxed
      require-lowercase: true           # Keep basic requirement
      require-digits: true              # Keep basic requirement
      require-special-chars: false      # Relaxed for testing
      prevent-common-passwords: false   # Allow weak passwords in dev
```

**Valid dev passwords:** `test123`, `dev456`, `simple1`

### Testing Environment (Minimal)

For automated testing:

```yaml
# application-test.yml
spring:
  config:
    activate:
      on-profile: test

ricardo:
  auth:
    password-policy:
      min-length: 4                     # Very short for tests
      require-uppercase: false
      require-lowercase: false
      require-digits: false
      require-special-chars: false
      prevent-common-passwords: false   # Allow any password
```

**Valid test passwords:** `test`, `1234`, `abc`

### Production Environment (Strict)

For maximum security in production:

```yaml
# application-prod.yml
spring:
  config:
    activate:
      on-profile: prod

ricardo:
  auth:
    password-policy:
      min-length: 12                    # Stronger for production
      max-length: 128
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      special-characters: "!@#$%^&*()_+-=[]{}|;:,.<>?"
      prevent-common-passwords: true
```

**Required prod passwords:** `MyVerySecure@Password123!`

### Mobile-Friendly Configuration

For mobile applications where special characters are harder to type:

```yaml
# Mobile-optimized policy
ricardo:
  auth:
    password-policy:
      min-length: 8
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: false      # Disabled for mobile keyboards
      prevent-common-passwords: true
```

**Valid mobile passwords:** `MobileApp123`, `SecureLogin99`

## 🌍 Environment Variable Configuration

### Setting via Environment Variables

```bash
# Password policy environment variables
export RICARDO_AUTH_PASSWORD_POLICY_MIN_LENGTH=10
export RICARDO_AUTH_PASSWORD_POLICY_REQUIRE_UPPERCASE=true
export RICARDO_AUTH_PASSWORD_POLICY_REQUIRE_LOWERCASE=true
export RICARDO_AUTH_PASSWORD_POLICY_REQUIRE_DIGITS=true
export RICARDO_AUTH_PASSWORD_POLICY_REQUIRE_SPECIAL_CHARS=true
export RICARDO_AUTH_PASSWORD_POLICY_PREVENT_COMMON_PASSWORDS=true
```

### Using Environment Variables in Configuration

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
      special-characters: ${RICARDO_AUTH_PASSWORD_POLICY_SPECIAL_CHARS:!@#$%^&*()}
```

### Docker Environment Variables

```bash
# docker-compose.yml
version: '3.8'
services:
  app:
    image: my-app:latest
    environment:
      - RICARDO_AUTH_PASSWORD_POLICY_MIN_LENGTH=12
      - RICARDO_AUTH_PASSWORD_POLICY_REQUIRE_SPECIAL_CHARS=true
      - RICARDO_AUTH_PASSWORD_POLICY_PREVENT_COMMON_PASSWORDS=true
```

## 🎯 Use Case Examples

### 1. SaaS Application

**Requirements:** Balanced security and usability for business users

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 8
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      special-characters: "!@#$%^&*"    # Common keyboard symbols
      prevent-common-passwords: true
```

**Valid passwords:** `Business@123`, `SecureApp1!`, `MyLogin$99`

### 2. Financial/Healthcare Application

**Requirements:** High security compliance

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 15                    # Long passwords
      max-length: 64                    # Reasonable maximum
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      special-characters: "!@#$%^&*()_+-=[]{}|;:,.<>?"
      prevent-common-passwords: true
```

**Valid passwords:** `MyVerySecure@Password123!`, `HighSecurity$App2024#`

### 3. Consumer Mobile App

**Requirements:** User-friendly for mobile devices

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 8
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: false      # Mobile keyboards limitation
      prevent-common-passwords: true
```

**Valid passwords:** `MobileApp123`, `SecureLogin99`, `MyPhone2024`

### 4. Educational Platform

**Requirements:** Simple for students and teachers

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

**Valid passwords:** `student123`, `teacher456`, `school2024`

### 5. Internal Corporate Tool

**Requirements:** Strong security for employee access

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

**Valid passwords:** `CorporateAccess@2024!`, `EmployeeLogin$123`

## 🔒 Security Considerations

### Password Strength vs Usability

**High Security (Financial, Healthcare):**

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 15
      require-special-chars: true
      prevent-common-passwords: true
```

**Balanced Security (Most Applications):**

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 10
      require-special-chars: true
      prevent-common-passwords: true
```

**User-Friendly (Consumer Apps):**

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 8
      require-special-chars: false  # For mobile
      prevent-common-passwords: true
```

### Special Characters Configuration

#### Standard Set (Recommended)

```yaml
ricardo:
  auth:
    password-policy:
      special-characters: "!@#$%^&*()"  # Common keyboard symbols
```

#### Extended Set

```yaml
ricardo:
  auth:
    password-policy:
      special-characters: "!@#$%^&*()_+-=[]{}|;:,.<>?"  # More symbols
```

#### Minimal Set (Mobile-Friendly)

```yaml
ricardo:
  auth:
    password-policy:
      special-characters: "!@#$"  # Easy to type on mobile
```

#### Custom Set

```yaml
ricardo:
  auth:
    password-policy:
      special-characters: "!@#$%"  # Only specific symbols allowed
```

## 📝 Custom Password Blacklist

### Using Custom Password File

1. **Create password blacklist file:**
   ```text
   # src/main/resources/custom-passwords.txt
   companyname123
   organization2024
   department123
   projectname
   teamname123
   ```

2. **Configure the file path:**
   ```yaml
   ricardo:
     auth:
       password-policy:
         common-passwords-file: "/custom-passwords.txt"
   ```

3. **File format:**
    - One password per line
    - Case-insensitive matching
    - Comments start with `#`
    - Empty lines are ignored

### Built-in Common Passwords

Ricardo Auth includes protection against common passwords like:

- `password`, `password123`, `123456`
- `qwerty`, `admin`, `login`
- `welcome`, `letmein`, `monkey`
- Sequential patterns: `123456`, `abcdef`

## 🧪 Testing Password Policies

### Test Valid Passwords

```bash
#!/bin/bash

BASE_URL="http://localhost:8080"

# Test valid passwords
declare -a valid_passwords=(
    "MySecure@Pass123!"
    "StrongPassword1!"
    "ValidLogin$456"
    "GoodPassword#789"
)

echo "Testing valid passwords..."
for password in "${valid_passwords[@]}"; do
    echo "Testing: $password"
    
    response=$(curl -s -X POST "$BASE_URL/api/users/create" \
        -H "Content-Type: application/json" \
        -d "{
            \"username\": \"test$(date +%s)\",
            \"email\": \"test$(date +%s)@example.com\",
            \"password\": \"$password\"
        }")
    
    if echo "$response" | grep -q '"id"'; then
        echo "✅ Password accepted"
    else
        echo "❌ Password rejected: $(echo "$response" | jq -r '.message')"
    fi
    echo ""
done
```

### Test Invalid Passwords

```bash
# Test invalid passwords
declare -a invalid_passwords=(
    "weak"                    # Too short
    "password123"             # Common password
    "nouppercase123!"         # No uppercase
    "NOLOWERCASE123!"         # No lowercase
    "NoDigits!"               # No digits
    "NoSpecialChars123"       # No special chars
)

echo "Testing invalid passwords..."
for password in "${invalid_passwords[@]}"; do
    echo "Testing: $password"
    
    response=$(curl -s -X POST "$BASE_URL/api/users/create" \
        -H "Content-Type: application/json" \
        -d "{
            \"username\": \"test$(date +%s)\",
            \"email\": \"test$(date +%s)@example.com\",
            \"password\": \"$password\"
        }")
    
    if echo "$response" | grep -q '"error"'; then
        echo "✅ Password correctly rejected"
        echo "   Reason: $(echo "$response" | jq -r '.message')"
    else
        echo "❌ Password incorrectly accepted"
    fi
    echo ""
done
```

## 🔄 Migration Strategies

### Migrating from Previous Versions

If upgrading from Ricardo Auth v1.0.x:

#### Phase 1: Soft Migration

```yaml
# Relaxed policy for existing users
ricardo:
  auth:
    password-policy:
      min-length: 6             # Lower than new default
      require-special-chars: false
      prevent-common-passwords: false
```

#### Phase 2: Gradual Strengthening

```yaml
# Gradually increase requirements
ricardo:
  auth:
    password-policy:
      min-length: 8
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      # Special chars still disabled
```

#### Phase 3: Full Security

```yaml
# Final secure configuration
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

### Handling Existing Users

```java
// Example: Force password update for existing users
@Service
public class PasswordMigrationService {

    public boolean needsPasswordUpdate(User user) {
        // Check if user's password meets current policy
        return !passwordPolicyService.isPasswordCompliant(user.getPassword());
    }

    @PostMapping("/auth/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        User user = authenticateUser(request);
        String token = generateToken(user);

        boolean requirePasswordUpdate = needsPasswordUpdate(user);

        return ResponseEntity.ok(new LoginResponse(
                token,
                user.getUsername(),
                requirePasswordUpdate
        ));
    }
}
```

## 📊 Performance Considerations

### Common Password Check Performance

The common password check is optimized but can be tuned:

#### Disable for Development

```yaml
# Faster development builds
spring:
  config:
    activate:
      on-profile: dev

ricardo:
  auth:
    password-policy:
      prevent-common-passwords: false  # Skip check in dev
```

#### Monitor Performance

```yaml
# Enable performance logging
logging:
  level:
    com.ricardo.auth.core.PasswordPolicyService: DEBUG
```

#### Custom Performance Optimization

```java
// Cache common passwords for better performance
@Component
public class OptimizedPasswordValidator {

    private final Set<String> commonPasswords = loadCommonPasswords();

    public boolean isCommonPassword(String password) {
        return commonPasswords.contains(password.toLowerCase());
    }
}
```

## 🎨 Frontend Integration

### Password Strength Indicator

```javascript
// Real-time password validation
function validatePasswordStrength(password) {
    const requirements = {
        length: password.length >= 8,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        digits: /\d/.test(password),
        special: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)
    };

    const strength = Object.values(requirements).filter(Boolean).length;

    return {
        requirements,
        strength,
        isValid: strength === 5
    };
}

// Update UI indicators
function updatePasswordStrength(password) {
    const validation = validatePasswordStrength(password);

    // Update requirement indicators
    Object.entries(validation.requirements).forEach(([req, met]) => {
        const indicator = document.getElementById(`req-${req}`);
        indicator.className = met ? 'text-success' : 'text-muted';
        indicator.textContent = met ? '✓' : '○';
    });

    // Update strength bar
    const strengthBar = document.getElementById('strength-bar');
    strengthBar.style.width = `${(validation.strength / 5) * 100}%`;
    strengthBar.className = `progress-bar bg-${getStrengthColor(validation.strength)}`;
}

function getStrengthColor(strength) {
    if (strength <= 2) return 'danger';
    if (strength <= 3) return 'warning';
    if (strength <= 4) return 'info';
    return 'success';
}
```

### Password Requirements Display

```html
<!-- Password requirements checklist -->
<div class="password-requirements">
    <h6>Password Requirements:</h6>
    <ul class="list-unstyled">
        <li id="req-length" class="text-muted">○ At least 8 characters</li>
        <li id="req-uppercase" class="text-muted">○ One uppercase letter (A-Z)</li>
        <li id="req-lowercase" class="text-muted">○ One lowercase letter (a-z)</li>
        <li id="req-digits" class="text-muted">○ One number (0-9)</li>
        <li id="req-special" class="text-muted">○ One special character (!@#$%^&*)</li>
    </ul>

    <!-- Strength indicator -->
    <div class="progress mt-2" style="height: 6px;">
        <div id="strength-bar" class="progress-bar" style="width: 0%"></div>
    </div>
</div>
```

## 🆘 Troubleshooting

### Common Configuration Issues

#### 1. Policy Not Applied

```yaml
# ❌ Wrong indentation
ricardo:
auth:
  password-policy:
    min-length: 8

# ✅ Correct indentation
ricardo:
  auth:
    password-policy:
      min-length: 8
```

#### 2. Environment Variables Not Working

```bash
# ❌ Wrong variable name
export RICARDO_PASSWORD_MIN_LENGTH=8

# ✅ Correct variable name
export RICARDO_AUTH_PASSWORD_POLICY_MIN_LENGTH=8
```

#### 3. Profile-Specific Configuration Not Loading

```yaml
# ❌ Wrong profile syntax
spring.profiles.active: dev

# ✅ Correct profile syntax
spring:
  config:
    activate:
      on-profile: dev
```

### Validation Issues

See the [Password Policy Troubleshooting Guide](../troubleshooting/password-policy.md) for detailed solutions to
validation errors.

## 🔗 Related Documentation

- **[Password Policy Examples](../examples/password-policy.md)** - Real-world examples and use cases
- **[Password Policy Troubleshooting](../troubleshooting/password-policy.md)** - Common issues and solutions
- **[Security Configuration](security.md)** - Complete security setup
- **[Environment Variables](environment.md)** - Secure configuration management

---

🔒 **Strong passwords are your first line of defense!** Choose the right policy configuration for your security needs and
user experience requirements.
