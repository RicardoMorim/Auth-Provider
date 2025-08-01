# Password Policy Troubleshooting

Quick solutions for password policy validation issues in Ricardo Auth v1.1.0+.

## 🆘 Quick Fixes

**Password rejected during registration?** → [Check Error Message](#common-error-messages)  
**Policy too strict for testing?** → [Use Development Profile](#development-environment-setup)  
**Users can't create passwords?** → [User-Friendly Configuration](#user-friendly-policies)  
**Need to bypass validation?** → [Disable Policy](#disabling-password-policy)

---

## Common Error Messages


**❌ Error:**
```json
{
  "error": "Bad Request",
  "message": "Password must be at least 8 characters long",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**✅ Solutions:**

1. **Use a longer password:**
   ```bash
   # ❌ Too short (6 characters)
   curl -X POST http://localhost:8080/api/users/create \
     -d '{"password": "Test12"}'
   
   # ✅ Correct length (8+ characters)
   curl -X POST http://localhost:8080/api/users/create \
     -d '{"password": "TestPass123!"}'
   ```

2. **Adjust minimum length for testing:**
   ```yaml
   ricardo:
     auth:
       password-policy:
         min-length: 6  # Reduced for testing
   ```

### 2. "Password must contain at least one uppercase letter"

**❌ Error:**
```json
{
  "error": "Bad Request",
  "message": "Password must contain at least one uppercase letter",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**✅ Solutions:**

1. **Add uppercase letters (A-Z):**
   ```bash
   # ❌ No uppercase
   curl -X POST http://localhost:8080/api/users/create \
     -d '{"password": "testpass123!"}'
   
   # ✅ Has uppercase
   curl -X POST http://localhost:8080/api/users/create \
     -d '{"password": "TestPass123!"}'
   ```

2. **Disable uppercase requirement:**
   ```yaml
   ricardo:
     auth:
       password-policy:
         require-uppercase: false
   ```

### 3. "Password must contain at least one lowercase letter"

**❌ Error:**
```json
{
  "error": "Bad Request",
  "message": "Password must contain at least one lowercase letter",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**✅ Solutions:**

1. **Add lowercase letters (a-z):**
   ```bash
   # ❌ No lowercase
   curl -X POST http://localhost:8080/api/users/create \
     -d '{"password": "TESTPASS123!"}'
   
   # ✅ Has lowercase
   curl -X POST http://localhost:8080/api/users/create \
     -d '{"password": "TestPass123!"}'
   ```

2. **Disable lowercase requirement:**
   ```yaml
   ricardo:
     auth:
       password-policy:
         require-lowercase: false
   ```

### 4. "Password must contain at least one digit"

**❌ Error:**
```json
{
  "error": "Bad Request",
  "message": "Password must contain at least one digit",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**✅ Solutions:**

1. **Add digits (0-9):**
   ```bash
   # ❌ No digits
   curl -X POST http://localhost:8080/api/users/create \
     -d '{"password": "TestPassword!"}'
   
   # ✅ Has digits
   curl -X POST http://localhost:8080/api/users/create \
     -d '{"password": "TestPass123!"}'
   ```

2. **Disable digit requirement:**
   ```yaml
   ricardo:
     auth:
       password-policy:
         require-digits: false
   ```

### 5. "Password must contain at least one special character"

**❌ Error:**
```json
{
  "error": "Bad Request",
  "message": "Password must contain at least one special character",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**✅ Solutions:**

1. **Add special characters:**
   ```bash
   # ❌ No special characters
   curl -X POST http://localhost:8080/api/users/create \
     -d '{"password": "TestPass123"}'
   
   # ✅ Has special characters
   curl -X POST http://localhost:8080/api/users/create \
     -d '{"password": "TestPass123!"}'
   ```

2. **Check allowed special characters:**
   ```yaml
   ricardo:
     auth:
       password-policy:
         special-characters: "!@#$%^&*()_+-=[]{}|;:,.<>?"
   ```

3. **Disable special character requirement:**
   ```yaml
   ricardo:
     auth:
       password-policy:
         require-special-chars: false
   ```

### 6. "Password is too common and easily guessable"

- The system ships with a default block-list of common passwords. Disable it with `prevent-common-passwords: false`.
- You can point to a custom list through `common-passwords-file`.

**❌ Error:**
```json
{
  "error": "Bad Request",
  "message": "Password is too common and easily guessable",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**✅ Solutions:**

1. **Avoid common passwords:**
   ```bash
   # ❌ Common passwords to avoid
   "password123"
   "123456789"
   "qwerty123"
   "welcome123"
   "admin123"
   "letmein123"
   
   # ✅ Use unique passwords
   "MyUniqueApp2024!"
   "SecureLogin@789"
   "PersonalPass#456"
   ```

2. **Disable common password check (not recommended):**
   ```yaml
   ricardo:
     auth:
       password-policy:
         prevent-common-passwords: false
   ```

### 7. "Password exceeds maximum length"

**❌ Error:**
```json
{
  "error": "Bad Request",
  "message": "Password must not exceed 128 characters",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**✅ Solutions:**

1. **Use shorter password:**
   ```bash
   # Keep passwords under the maximum length (default: 128 characters)
   ```

2. **Increase maximum length:**
   ```yaml
   ricardo:
     auth:
       password-policy:
         max-length: 256  # Increased limit
   ```

## Environment-Specific Solutions

### Development Environment Setup

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

**Test with relaxed policy:**
```bash
# Start with dev profile
java -jar app.jar --spring.profiles.active=dev

# Test with simple password
curl -X POST http://localhost:8080/api/users/create \
  -d '{"username":"dev","email":"dev@test.com","password":"test123"}'
```

### Testing Environment Setup

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

### Production Environment Setup

> **Dica:**
> - Use blocklist de senhas e ajuste os requisitos para apps sensíveis.
> - Combine com rate limiting para máxima proteção contra brute force.

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
      prevent-common-passwords: true
```

## User-Friendly Policies

### Mobile-Friendly Configuration

For mobile applications where special characters are harder to type:

```yaml
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

### Gradual Policy Implementation

Implement stricter policies over time:

#### Phase 1: Basic Requirements
```yaml
ricardo:
  auth:
    password-policy:
      min-length: 8
      require-digits: true
      prevent-common-passwords: true
      # Other requirements disabled initially
```

#### Phase 2: Add Character Types
```yaml
ricardo:
  auth:
    password-policy:
      min-length: 8
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      prevent-common-passwords: true
```

#### Phase 3: Full Security
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
```

## Frontend Error Handling

### Display User-Friendly Messages

```javascript
function handlePasswordError(error) {
    const requirements = {
        'uppercase': 'Include uppercase letters (A-Z)',
        'lowercase': 'Include lowercase letters (a-z)',
        'digits': 'Include numbers (0-9)',
        'special': 'Include special characters (!@#$%^&*)',
        'length': 'Use at least 8 characters',
        'common': 'Choose a unique password'
    };
    
    let message = 'Password requirements:<ul>';
    
    // Parse error and show relevant requirements
    if (error.includes('uppercase')) {
        message += `<li>${requirements.uppercase}</li>`;
    }
    if (error.includes('lowercase')) {
        message += `<li>${requirements.lowercase}</li>`;
    }
    if (error.includes('digit')) {
        message += `<li>${requirements.digits}</li>`;
    }
    if (error.includes('special')) {
        message += `<li>${requirements.special}</li>`;
    }
    if (error.includes('characters long')) {
        message += `<li>${requirements.length}</li>`;
    }
    if (error.includes('common')) {
        message += `<li>${requirements.common}</li>`;
    }
    
    message += '</ul>';
    
    document.getElementById('password-error').innerHTML = message;
}
```

### Real-Time Password Validation

```javascript
function validatePasswordRealTime(password) {
    const requirements = {
        length: password.length >= 8,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        digits: /\d/.test(password),
        special: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)
    };
    
    updateRequirementIndicator('length', requirements.length);
    updateRequirementIndicator('uppercase', requirements.uppercase);
    updateRequirementIndicator('lowercase', requirements.lowercase);
    updateRequirementIndicator('digits', requirements.digits);
    updateRequirementIndicator('special', requirements.special);
    
    return Object.values(requirements).every(req => req);
}

function updateRequirementIndicator(requirement, met) {
    const indicator = document.getElementById(`req-${requirement}`);
    if (met) {
        indicator.classList.add('text-success');
        indicator.classList.remove('text-danger');
        indicator.innerHTML = '✓';
    } else {
        indicator.classList.add('text-danger');
        indicator.classList.remove('text-success');
        indicator.innerHTML = '✗';
    }
}
```

## Disabling Password Policy

### Temporary Disable (Not Recommended)

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 1                     # Minimal requirement
      require-uppercase: false
      require-lowercase: false
      require-digits: false
      require-special-chars: false
      prevent-common-passwords: false
```

### Complete Disable (Not Recommended for Production)

Currently, password policy cannot be completely disabled. The minimum configuration is:

```yaml
ricardo:
  auth:
    password-policy:
      min-length: 1  # Minimum possible value
```

## Testing Password Policies

### Test Script for Validation

```bash
#!/bin/bash

echo "Testing Password Policy Configuration..."

BASE_URL="http://localhost:8080"

# Test cases
declare -a passwords=(
    "weak"
    "password123"  
    "TestPassword"
    "testpass123!"
    "TESTPASS123!"
    "TestPass123!"
)

for password in "${passwords[@]}"; do
    echo "Testing password: $password"
    
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
        echo "❌ Password rejected"
        echo "   Reason: $(echo "$response" | jq -r '.message' 2>/dev/null || echo "$response")"
    fi
    echo ""
done
```

### Unit Test Example

```java
@Test
public void testPasswordPolicyValidation() {
    // Configure test policy
    PasswordPolicy policy = PasswordPolicy.builder()
        .minLength(8)
        .requireUppercase(true)
        .requireLowercase(true)
        .requireDigits(true)
        .requireSpecialChars(true)
        .build();
    
    // Test valid password
    assertThat(policy.validate("ValidPass123!")).isTrue();
    
    // Test invalid passwords
    assertThatThrownBy(() -> policy.validate("short"))
        .hasMessageContaining("characters long");
        
    assertThatThrownBy(() -> policy.validate("nouppercase123!"))
        .hasMessageContaining("uppercase letter");
        
    assertThatThrownBy(() -> policy.validate("NOLOWERCASE123!"))
        .hasMessageContaining("lowercase letter");
        
    assertThatThrownBy(() -> policy.validate("NoDigits!"))
        .hasMessageContaining("digit");
        
    assertThatThrownBy(() -> policy.validate("NoSpecialChars123"))
        .hasMessageContaining("special character");
}
```

## Performance Considerations

### Common Password Check Performance

If common password checking is slow:

1. **Disable for development:**
   ```yaml
   ricardo:
     auth:
       password-policy:
         prevent-common-passwords: false
   ```

2. **Use smaller password list:**
   ```yaml
   ricardo:
     auth:
       password-policy:
         common-passwords-file: "/small-passwords-list.txt"
   ```

3. **Monitor performance:**
   ```yaml
   logging:
     level:
       com.ricardo.auth.core.PasswordPolicyService: DEBUG
   ```

## Configuration Validation

### Check Current Policy

```bash
# Get current configuration
curl http://localhost:8080/actuator/configprops | jq '.ricardo.auth.passwordPolicy'
```

### Validate Configuration

```java
@Component
public class PasswordPolicyValidator {
    
    @EventListener
    public void validateConfiguration(ApplicationReadyEvent event) {
        // Validate policy configuration at startup
        PasswordPolicyProperties policy = passwordPolicyProperties;
        
        if (policy.getMinLength() < 1) {
            log.warn("Minimum password length is too low: {}", policy.getMinLength());
        }
        
        if (policy.getMaxLength() < policy.getMinLength()) {
            log.error("Maximum length ({}) is less than minimum length ({})", 
                     policy.getMaxLength(), policy.getMinLength());
        }
        
        log.info("Password policy configuration validated successfully");
    }
}
```

## Migration Guide


If you're upgrading from a previous version:

1. **Existing users may have weak passwords:**
   ```yaml
   # Temporary relaxed policy during migration
   ricardo:
     auth:
       password-policy:
         min-length: 6  # Lower than new default
   ```

2. **Gradually strengthen policy:**
   - Start with relaxed requirements
   - Notify users of upcoming changes
   - Gradually increase requirements
   - Force password updates at next login

3. **Handle existing user authentication:**
   ```java
   // Existing users with weak passwords can still log in
   // Force password update on next login
   @PostMapping("/auth/login")
   public ResponseEntity<?> login(@RequestBody LoginRequest request) {
       // Authenticate user
       User user = authenticateUser(request);
       
       // Check if password meets current policy
       if (!passwordPolicyService.isPasswordCompliant(user.getPassword())) {
           return ResponseEntity.ok(new LoginResponse(token, true)); // requirePasswordUpdate: true
       }
       
       return ResponseEntity.ok(new LoginResponse(token, false));
   }
   ```

## 🆘 Still Having Issues?

### Check These Common Causes

1. **Configuration not loaded:**
   - Verify `application.yml` syntax
   - Check active Spring profiles
   - Ensure configuration is in correct file

2. **Caching issues:**
   - Restart application
   - Clear configuration cache
   - Check for multiple configuration files

3. **Version compatibility:**
   - Ensure using Ricardo Auth v1.1.0+
   - Check Spring Boot compatibility
   - Verify all dependencies are compatible

### Get Help

If you're still having issues:

1. **Enable debug logging:**
   ```yaml
   logging:
     level:
       com.ricardo.auth: DEBUG
   ```

2. **Share your configuration** (remove secrets!)

3. **Include error messages** and stack traces

4. **Ask for help:**
   - 🐛 [GitHub Issues](https://github.com/RicardoMorim/Auth-Provider/issues)
   - 💬 [GitHub Discussions](https://github.com/RicardoMorim/Auth-Provider/discussions)

---

🔒 **Remember:** Password policies are crucial for security. Balance security requirements with user experience for the best results!
