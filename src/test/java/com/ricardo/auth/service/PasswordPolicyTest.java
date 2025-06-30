package com.ricardo.auth.service;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.PasswordPolicyService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for PasswordPolicy service.
 * Tests password validation rules and policy enforcement.
 */
class PasswordPolicyTest {

    private PasswordPolicyService passwordPolicyService;
    private AuthProperties authProperties;

    /**
     * Sets up.
     */
    @BeforeEach
    void setUp() {
        authProperties = new AuthProperties();
        // Configure test properties
        authProperties.getPasswordPolicy().setMinLength(8);
        authProperties.getPasswordPolicy().setMaxLength(60);
        authProperties.getPasswordPolicy().setRequireUppercase(true);
        authProperties.getPasswordPolicy().setRequireLowercase(true);
        authProperties.getPasswordPolicy().setRequireDigits(true);
        authProperties.getPasswordPolicy().setRequireSpecialChars(false);
        authProperties.getPasswordPolicy().setPreventCommonPasswords(true);

        passwordPolicyService = new PasswordPolicy(authProperties);
    }

    // ========== VALID PASSWORD TESTS ==========

    /**
     * Validate password should return true when password meets all requirements.
     */
    @Test
    void validatePassword_shouldReturnTrue_whenPasswordMeetsAllRequirements() {
        // Act & Assert - Should not throw exceptions
        assertDoesNotThrow(() -> passwordPolicyService.validatePassword("ValidPass123"));
        assertDoesNotThrow(() -> passwordPolicyService.validatePassword("MySecure1"));
        assertDoesNotThrow(() -> passwordPolicyService.validatePassword("Test123Password"));

        // Also verify return value is true
        assertTrue(passwordPolicyService.validatePassword("ValidPass123"));
        assertTrue(passwordPolicyService.validatePassword("MySecure1"));
        assertTrue(passwordPolicyService.validatePassword("Test123Password"));
    }

    // ========== LENGTH VALIDATION TESTS ==========

    /**
     * Validate password should throw exception when password too short.
     */
    @Test
    void validatePassword_shouldThrowException_whenPasswordTooShort() {
        // Act & Assert - Should throw IllegalArgumentException with meaningful message
        IllegalArgumentException exception1 = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword("Abc1"));     // 4 chars
        assertTrue(exception1.getMessage().contains("at least 8 characters"));

        IllegalArgumentException exception2 = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword("Test1"));   // 5 chars
        assertTrue(exception2.getMessage().contains("at least 8 characters"));

        IllegalArgumentException exception3 = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword("Pass1"));    // 5 chars
        assertTrue(exception3.getMessage().contains("at least 8 characters"));
    }

    /**
     * Validate password should throw exception when password too long.
     */
    @Test
    void validatePassword_shouldThrowException_whenPasswordTooLong() {
        // Arrange
        String longPassword = "ValidPass@123" + "a".repeat(120);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword(longPassword));
        assertTrue(exception.getMessage().contains("must not exceed 60 characters"));
    }

    /**
     * Validate password should return true when password at boundaries.
     */
    @Test
    void validatePassword_shouldReturnTrue_whenPasswordAtBoundaries() {
        // Act & Assert - Exactly 8 characters (minimum)
        assertDoesNotThrow(() -> passwordPolicyService.validatePassword("ValidP1a"));
        assertTrue(passwordPolicyService.validatePassword("ValidP1a"));

        // Exactly 60 characters (maximum)
        String maxPassword = "ValidP@1a" + "a".repeat(51);
        assertDoesNotThrow(() -> passwordPolicyService.validatePassword(maxPassword));
        assertTrue(passwordPolicyService.validatePassword(maxPassword));
    }

    // ========== CHARACTER REQUIREMENT TESTS ==========

    /**
     * Validate password should throw exception when missing uppercase.
     */
    @Test
    void validatePassword_shouldThrowException_whenMissingUppercase() {
        // Act & Assert
        IllegalArgumentException exception1 = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword("validpass123"));
        assertTrue(exception1.getMessage().contains("uppercase letter"));

        IllegalArgumentException exception2 = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword("mypassword1"));
        assertTrue(exception2.getMessage().contains("uppercase letter"));
    }

    /**
     * Validate password should throw exception when missing lowercase.
     */
    @Test
    void validatePassword_shouldThrowException_whenMissingLowercase() {
        // Act & Assert
        IllegalArgumentException exception1 = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword("VALIDPASS123"));
        assertTrue(exception1.getMessage().contains("lowercase letter"));

        IllegalArgumentException exception2 = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword("MYPASSWORD1"));
        assertTrue(exception2.getMessage().contains("lowercase letter"));
    }

    /**
     * Validate password should throw exception when missing digits.
     */
    @Test
    void validatePassword_shouldThrowException_whenMissingDigits() {
        // Act & Assert
        IllegalArgumentException exception1 = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword("ValidPassword"));
        assertTrue(exception1.getMessage().contains("digit"));

        IllegalArgumentException exception2 = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword("MyPassword"));
        assertTrue(exception2.getMessage().contains("digit"));
    }

    /**
     * Validate password should throw exception when password is common.
     *
     * @param commonPassword the common password
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "password",           // Common password
            "123456",            // Common password
            "password123",       // Common password + digits
            "admin",             // Common password
            "qwerty"             // Common password
    })
    void validatePassword_shouldThrowException_whenPasswordIsCommon(String commonPassword) {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword(commonPassword));
        assertTrue(exception.getMessage().contains("too common") ||
                exception.getMessage().contains("at least 8 characters"));
    }

    // ========== NULL AND EMPTY TESTS ==========

    /**
     * Validate password should throw exception when password is null.
     */
    @Test
    void validatePassword_shouldThrowException_whenPasswordIsNull() {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword(null));
        assertTrue(exception.getMessage().contains("at least") ||
                exception.getMessage().contains("characters"));
    }

    /**
     * Validate password should throw exception when password is empty.
     */
    @Test
    void validatePassword_shouldThrowException_whenPasswordIsEmpty() {
        // Act & Assert
        IllegalArgumentException exception1 = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword(""));
        assertTrue(exception1.getMessage().contains("at least") ||
                exception1.getMessage().contains("characters"));

        IllegalArgumentException exception2 = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword("   "));
        assertTrue(exception2.getMessage().contains("at least") ||
                exception2.getMessage().contains("characters"));
    }

    // ========== SPECIAL CHARACTERS TESTS ==========

    /**
     * Validate password should throw exception when special char required but missing.
     */
    @Test
    void validatePassword_shouldThrowException_whenSpecialCharRequiredButMissing() {
        // Arrange - Enable special characters requirement
        authProperties.getPasswordPolicy().setRequireSpecialChars(true);
        passwordPolicyService = new PasswordPolicy(authProperties);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword("ValidPass123")); // No special chars
        assertTrue(exception.getMessage().contains("special character"));

        // Should succeed with special chars
        assertDoesNotThrow(() -> passwordPolicyService.validatePassword("ValidPass123!")); // Has special char
        assertTrue(passwordPolicyService.validatePassword("ValidPass123!"));

        assertDoesNotThrow(() -> passwordPolicyService.validatePassword("MyPass1@"));      // Has special char
        assertTrue(passwordPolicyService.validatePassword("MyPass1@"));
    }

    /**
     * Validate password should ignore special char requirement when disabled.
     */
    @Test
    void validatePassword_shouldIgnoreSpecialCharRequirement_whenDisabled() {
        // Arrange - Disable special characters requirement (default in setup)

        // Act & Assert
        assertDoesNotThrow(() -> passwordPolicyService.validatePassword("ValidPass123"));  // No special chars - should pass
        assertTrue(passwordPolicyService.validatePassword("ValidPass123"));

        assertDoesNotThrow(() -> passwordPolicyService.validatePassword("ValidPass123!")); // With special chars - should also pass
        assertTrue(passwordPolicyService.validatePassword("ValidPass123!"));
    }

    // ========== CONFIGURATION TESTS ==========

    /**
     * Validate password should respect custom min length.
     */
    @Test
    void validatePassword_shouldRespectCustomMinLength() {
        // Arrange
        authProperties.getPasswordPolicy().setMinLength(12);
        passwordPolicyService = new PasswordPolicy(authProperties);

        // Act & Assert
        IllegalArgumentException exception1 = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword("ValidP1"));    // 7 chars - too short
        assertTrue(exception1.getMessage().contains("at least 12 characters"));

        IllegalArgumentException exception2 = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword("ValidPas1"));  // 9 chars - still too short
        assertTrue(exception2.getMessage().contains("at least 12 characters"));

        IllegalArgumentException exception3 = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword("ValidPassw1"));  // 11 chars - still too short
        assertTrue(exception3.getMessage().contains("at least 12 characters"));

        // Should succeed with exactly minimum length
        assertDoesNotThrow(() -> passwordPolicyService.validatePassword("ValidPasswo1")); // 12 chars - exactly minimum
        assertTrue(passwordPolicyService.validatePassword("ValidPasswo1"));
    }

    /**
     * Validate password should allow disabling requirements.
     */
    @Test
    void validatePassword_shouldAllowDisablingRequirements() {
        // Arrange - Disable all character requirements
        authProperties.getPasswordPolicy().setRequireUppercase(false);
        authProperties.getPasswordPolicy().setRequireLowercase(false);
        authProperties.getPasswordPolicy().setRequireDigits(false);
        authProperties.getPasswordPolicy().setPreventCommonPasswords(false);
        passwordPolicyService = new PasswordPolicy(authProperties);

        // Act & Assert - Should only check length
        assertDoesNotThrow(() -> passwordPolicyService.validatePassword("password")); // 8 chars, previously common
        assertTrue(passwordPolicyService.validatePassword("password"));

        assertDoesNotThrow(() -> passwordPolicyService.validatePassword("12345678")); // 8 chars, only digits
        assertTrue(passwordPolicyService.validatePassword("12345678"));

        // Should still fail for too short
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword("short"));   // Too short
        assertTrue(exception.getMessage().contains("at least"));
    }

    // ========== GENERATE PASSWORD TESTS ==========

    /**
     * Generate secure password should create valid password.
     */
    @Test
    void generateSecurePassword_shouldCreateValidPassword() {
        // Act
        String generatedPassword = passwordPolicyService.generateSecurePassword();

        // Assert
        assertNotNull(generatedPassword);
        assertDoesNotThrow(() -> passwordPolicyService.validatePassword(generatedPassword));
        assertTrue(passwordPolicyService.validatePassword(generatedPassword));
        assertTrue(generatedPassword.length() >= 8);
    }

    /**
     * Generate secure password should create different passwords.
     */
    @Test
    void generateSecurePassword_shouldCreateDifferentPasswords() {
        // Act
        String password1 = passwordPolicyService.generateSecurePassword();
        String password2 = passwordPolicyService.generateSecurePassword();

        // Assert
        assertNotEquals(password1, password2);
    }

    // ========== EDGE CASES ==========

    /**
     * Validate password should handle unicode characters.
     */
    @Test
    void validatePassword_shouldHandleUnicodeCharacters() {
        // Act & Assert
        assertDoesNotThrow(() -> passwordPolicyService.validatePassword("ValidPäss123"));  // German umlaut
        assertTrue(passwordPolicyService.validatePassword("ValidPäss123"));

        assertDoesNotThrow(() -> passwordPolicyService.validatePassword("ValidPαss123"));  // Greek alpha
        assertTrue(passwordPolicyService.validatePassword("ValidPαss123"));

        assertDoesNotThrow(() -> passwordPolicyService.validatePassword("ValidP🔒ss123")); // Emoji
        assertTrue(passwordPolicyService.validatePassword("ValidP🔒ss123"));
    }

    /**
     * Validate password should handle whitespace.
     */
    @Test
    void validatePassword_shouldHandleWhitespace() {
        // Act & Assert
        assertDoesNotThrow(() -> passwordPolicyService.validatePassword("Valid Pass123"));  // Space in middle
        assertTrue(passwordPolicyService.validatePassword("Valid Pass123"));

        // Leading/trailing spaces should fail due to length after trimming
        IllegalArgumentException exception1 = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword(" ValidPa"));

        IllegalArgumentException exception2 = assertThrows(IllegalArgumentException.class,
                () -> passwordPolicyService.validatePassword("ValP123 "));
    }

    /**
     * Constructor should throw exception when invalid configuration.
     */
    @Test
    void constructor_shouldThrowException_whenInvalidConfiguration() {
        // Arrange
        authProperties.getPasswordPolicy().setMinLength(-1);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> {
            new PasswordPolicy(authProperties);
        });
    }

    /**
     * Constructor should throw exception when max length less than min length.
     */
    @Test
    void constructor_shouldThrowException_whenMaxLengthLessThanMinLength() {
        // Arrange
        authProperties.getPasswordPolicy().setMinLength(10);
        authProperties.getPasswordPolicy().setMaxLength(5);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> {
            new PasswordPolicy(authProperties);
        });
    }

    /**
     * Constructor should load common passwords when file exists.
     */
    @Test
    void constructor_shouldLoadCommonPasswords_whenFileExists() {
        // Arrange
        authProperties.getPasswordPolicy().setPreventCommonPasswords(true);

        // Act
        PasswordPolicyService service = new PasswordPolicy(authProperties);

        // Assert - Should throw exception for known common passwords
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> service.validatePassword("password123")); // Should be in common passwords file
        assertTrue(exception.getMessage().contains("too common") ||
                exception.getMessage().contains("security requirements"));
    }

    /**
     * Constructor should handle missing common passwords file gracefully.
     */
    @Test
    void constructor_shouldHandleMissingCommonPasswordsFile_gracefully() {
        // Arrange
        authProperties.getPasswordPolicy().setCommonPasswordsFilePath("/nonexistent.txt");
        authProperties.getPasswordPolicy().setPreventCommonPasswords(true);

        // Act & Assert - Should not throw exception, fall back to defaults
        assertDoesNotThrow(() -> {
            new PasswordPolicy(authProperties);
        });
    }
}