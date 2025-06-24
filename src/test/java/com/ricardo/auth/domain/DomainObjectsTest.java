package com.ricardo.auth.domain;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive tests for domain value objects and business logic.
 * Tests validation rules, edge cases, and business constraints.
 */
class DomainObjectsTest {

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    // ========== EMAIL TESTS ==========

    @Test
    void email_shouldCreateValidEmail() {
        // Act
        Email email = Email.valueOf("test@example.com");

        // Assert
        assertNotNull(email);
        assertEquals("test@example.com", email.getEmail());
    }

    @Test
    void email_shouldRejectNullValue() {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> Email.valueOf(null));
        assertEquals("Email cannot be null or empty", exception.getMessage());
    }

    @Test
    void email_shouldRejectEmptyValue() {
        // Act & Assert
        IllegalArgumentException exception1 = assertThrows(IllegalArgumentException.class, () -> Email.valueOf(""));
        assertEquals("Email cannot be null or empty", exception1.getMessage());
        
        IllegalArgumentException exception2 = assertThrows(IllegalArgumentException.class, () -> Email.valueOf("   "));
        assertEquals("Invalid email format", exception2.getMessage());
    }

    @Test
    void email_shouldRejectInvalidFormat() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> Email.valueOf("invalid-email"));
        assertThrows(IllegalArgumentException.class, () -> Email.valueOf("test@"));
        assertThrows(IllegalArgumentException.class, () -> Email.valueOf("@example.com"));
        assertThrows(IllegalArgumentException.class, () -> Email.valueOf("test.example.com"));
        assertThrows(IllegalArgumentException.class, () -> Email.valueOf("test@@example.com"));
    }

    @Test
    void email_shouldAcceptValidFormats() {
        // Act & Assert - Should not throw exceptions
        assertDoesNotThrow(() -> Email.valueOf("test@example.com"));
        assertDoesNotThrow(() -> Email.valueOf("user.name@domain.com"));
        assertDoesNotThrow(() -> Email.valueOf("test+tag@example.org"));
        assertDoesNotThrow(() -> Email.valueOf("test123@sub.domain.com"));
    }

    @Test
    void email_shouldNormalizeEmail() {
        // Act
        Email email = Email.valueOf("  Test@Example.Com  ");

        // Assert - Should be trimmed and lowercased
        assertEquals("test@example.com", email.getEmail());
    }

    @Test
    void email_shouldRejectTooLongEmail() {
        // Arrange
        String longEmail = "a".repeat(250) + "@example.com"; // Over 254 chars

        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> Email.valueOf(longEmail));
        assertEquals("Email cannot be longer than 254 characters", exception.getMessage());
    }

    @Test
    void email_shouldValidateEmailRegex() {
        // Act & Assert - Invalid characters
        assertThrows(IllegalArgumentException.class, () -> Email.valueOf("test space@example.com"));
        assertThrows(IllegalArgumentException.class, () -> Email.valueOf("test@exam ple.com"));
    }

    // ========== USERNAME TESTS ==========

    @Test
    void username_shouldCreateValidUsername() {
        // Act
        Username username = Username.valueOf("testuser");

        // Assert
        assertNotNull(username);
        assertEquals("testuser", username.getUsername());
    }

    @Test
    void username_shouldRejectNullValue() {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> Username.valueOf(null));
        assertEquals("Username cannot be null or empty", exception.getMessage());
    }

    @Test
    void username_shouldRejectEmptyValue() {
        // Act & Assert
        IllegalArgumentException exception1 = assertThrows(IllegalArgumentException.class, () -> Username.valueOf(""));
        assertEquals("Username cannot be null or empty", exception1.getMessage());
        
        IllegalArgumentException exception2 = assertThrows(IllegalArgumentException.class, () -> Username.valueOf("   "));
        assertEquals("Username can only contain letters, numbers, dots, underscores, and hyphens", exception2.getMessage());
    }

    @Test
    void username_shouldRejectTooShortUsername() {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> Username.valueOf("ab"));
        assertEquals("Username must be at least 3 characters long", exception.getMessage());
    }

    @Test
    void username_shouldRejectTooLongUsername() {
        // Act & Assert
        String longUsername = "a".repeat(21); // More than 20 chars
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> Username.valueOf(longUsername));
        assertEquals("Username cannot be longer than 20 characters", exception.getMessage());
    }

    @Test
    void username_shouldAcceptValidLengths() {
        // Act & Assert - Should not throw exceptions
        assertDoesNotThrow(() -> Username.valueOf("abc")); // 3 chars (minimum)
        assertDoesNotThrow(() -> Username.valueOf("a".repeat(20))); // 20 chars (maximum)
        assertDoesNotThrow(() -> Username.valueOf("normaluser"));
    }

    @Test
    void username_shouldAcceptValidCharacters() {
        // Act & Assert - Should not throw exceptions
        assertDoesNotThrow(() -> Username.valueOf("user_123"));
        assertDoesNotThrow(() -> Username.valueOf("user-name"));
        assertDoesNotThrow(() -> Username.valueOf("user.name"));
        assertDoesNotThrow(() -> Username.valueOf("User123"));
    }

    @Test
    void username_shouldRejectInvalidCharacters() {
        // Act & Assert
        IllegalArgumentException exception1 = assertThrows(IllegalArgumentException.class, () -> Username.valueOf("user space"));
        assertEquals("Username can only contain letters, numbers, dots, underscores, and hyphens", exception1.getMessage());
        
        IllegalArgumentException exception2 = assertThrows(IllegalArgumentException.class, () -> Username.valueOf("user@name"));
        assertEquals("Username can only contain letters, numbers, dots, underscores, and hyphens", exception2.getMessage());
    }

    @Test
    void username_shouldBeEqualBasedOnValue() {
        // Arrange
        Username username1 = Username.valueOf("testuser");
        Username username2 = Username.valueOf("testuser");
        Username username3 = Username.valueOf("differentuser");

        // Assert
        assertEquals(username1, username2);
        assertNotEquals(username1, username3);
        assertEquals(username1.hashCode(), username2.hashCode());
    }

    // ========== PASSWORD TESTS ==========

    @Test
    void password_shouldCreateValidPassword() {
        // Act
        Password password = Password.valueOf("password123", passwordEncoder);

        // Assert
        assertNotNull(password);
        assertNotNull(password.getHashed());
        assertTrue(passwordEncoder.matches("password123", password.getHashed()));
    }

    @Test
    void password_shouldRejectNullValue() {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> Password.valueOf(null, passwordEncoder));
        assertEquals("Password hash cannot be null or blank", exception.getMessage());
    }

    @Test
    void password_shouldRejectEmptyValue() {
        // Act & Assert
        IllegalArgumentException exception1 = assertThrows(IllegalArgumentException.class, () -> Password.valueOf("", passwordEncoder));
        assertEquals("Password hash cannot be null or blank", exception1.getMessage());
        
        IllegalArgumentException exception2 = assertThrows(IllegalArgumentException.class, () -> Password.valueOf("   ", passwordEncoder));
        assertEquals("Password hash cannot be null or blank", exception2.getMessage());
    }

    @Test
    void password_shouldRejectTooShortPassword() {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> Password.valueOf("123", passwordEncoder));
        assertEquals("Password hash must be at least 6 characters long", exception.getMessage());
    }

    @Test
    void password_shouldRejectTooLongPassword() {
        // Act & Assert
        String longPassword = "a".repeat(61); // More than 60 chars
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> Password.valueOf(longPassword, passwordEncoder));
        assertEquals("Password hash cannot be longer than 60 characters", exception.getMessage());
    }

    @Test
    void password_shouldAcceptValidLengths() {
        // Act & Assert - Should not throw exceptions
        assertDoesNotThrow(() -> Password.valueOf("123456", passwordEncoder)); // 6 chars (minimum)
        assertDoesNotThrow(() -> Password.valueOf("password123", passwordEncoder));
        assertDoesNotThrow(() -> Password.valueOf("a".repeat(60), passwordEncoder)); // 60 chars (maximum)
    }

    @Test
    void password_shouldHashPassword() {
        // Arrange
        String plainPassword = "password123";

        // Act
        Password password = Password.valueOf(plainPassword, passwordEncoder);

        // Assert
        assertNotEquals(plainPassword, password.getHashed());
        assertTrue(passwordEncoder.matches(plainPassword, password.getHashed()));
    }

    @Test
    void password_shouldProduceDifferentHashesForSamePassword() {
        // Arrange
        String plainPassword = "password123";

        // Act
        Password password1 = Password.valueOf(plainPassword, passwordEncoder);
        Password password2 = Password.valueOf(plainPassword, passwordEncoder);

        // Assert - Due to salt, hashes should be different but both valid
        assertNotEquals(password1.getHashed(), password2.getHashed());
        assertTrue(passwordEncoder.matches(plainPassword, password1.getHashed()));
        assertTrue(passwordEncoder.matches(plainPassword, password2.getHashed()));
    }

    @Test
    void password_shouldCreateFromExistingHash() {
        // Arrange
        String existingHash = "$2a$10$DowJonesHash1234567890123456789012345678901234567890";

        // Act
        Password password = Password.fromHash(existingHash);

        // Assert
        assertNotNull(password);
        assertEquals(existingHash, password.getHashed());
    }

    @Test
    void password_shouldRejectNullHash() {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> Password.fromHash(null));
        assertEquals("Password hash cannot be null or blank", exception.getMessage());
    }

    // ========== USER TESTS ==========

    @Test
    void user_shouldCreateValidUser() {
        // Arrange
        Username username = Username.valueOf("testuser");
        Email email = Email.valueOf("test@example.com");
        Password password = Password.valueOf("password123", passwordEncoder);

        // Act
        User user = new User(username, email, password);

        // Assert
        assertNotNull(user);
        assertEquals("testuser", user.getUsername());
        assertEquals("test@example.com", user.getEmail());
        assertTrue(passwordEncoder.matches("password123", user.getPassword()));
    }    @Test
    void user_shouldAddAndManageRoles() {
        // Arrange
        Username username = Username.valueOf("testuser");
        Email email = Email.valueOf("test@example.com");
        Password password = Password.valueOf("password123", passwordEncoder);
        User user = new User(username, email, password);

        // Act - Add roles
        user.addRole(AppRole.USER);
        user.addRole(AppRole.ADMIN);

        // Assert
        assertEquals(2, user.getRoles().size());
        assertTrue(user.getRoles().contains(AppRole.USER));
        assertTrue(user.getRoles().contains(AppRole.ADMIN));
        
        // Test that roles can be accessed through authorities
        var authorities = user.getAuthorities();
        assertEquals(2, authorities.size());
        assertTrue(authorities.stream().anyMatch(auth -> auth.getAuthority().equals("ROLE_USER")));
        assertTrue(authorities.stream().anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN")));
    }    @Test
    void user_shouldGetAuthorities() {
        // Arrange
        Username username = Username.valueOf("testuser");
        Email email = Email.valueOf("test@example.com");
        Password password = Password.valueOf("password123", passwordEncoder);
        User user = new User(username, email, password);
        user.addRole(AppRole.USER);
        user.addRole(AppRole.ADMIN);

        // Act
        var authorities = user.getAuthorities();

        // Assert
        assertEquals(2, authorities.size());
        assertTrue(authorities.stream().anyMatch(auth -> auth.getAuthority().equals("ROLE_USER")));
        assertTrue(authorities.stream().anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN")));
    }

    @Test
    void user_shouldImplementUserDetailsCorrectly() {
        // Arrange
        Username username = Username.valueOf("testuser");
        Email email = Email.valueOf("test@example.com");
        Password password = Password.valueOf("password123", passwordEncoder);
        User user = new User(username, email, password);

        // Assert UserDetails implementation
        assertEquals("testuser", user.getUsername());
        assertNotNull(user.getPassword());
        assertTrue(user.isAccountNonExpired());
        assertTrue(user.isAccountNonLocked());
        assertTrue(user.isCredentialsNonExpired());
        assertTrue(user.isEnabled());
    }

    // ========== APPROLE TESTS ==========

    @Test
    void appRole_shouldHaveCorrectAuthorities() {
        // Assert
        assertEquals("ROLE_USER", AppRole.USER.getAuthority());
        assertEquals("ROLE_ADMIN", AppRole.ADMIN.getAuthority());
    }

    @Test
    void appRole_shouldHaveCorrectNames() {
        // Assert
        assertEquals("USER", AppRole.USER.name());
        assertEquals("ADMIN", AppRole.ADMIN.name());
    }

    // ========== EDGE CASES AND BOUNDARY TESTS ==========

    @Test
    void email_shouldHandleMaximumValidLength() {
        // Arrange - 254 characters (maximum allowed)
        String maxEmail = "a".repeat(240) + "@example.com";

        // Act & Assert
        assertDoesNotThrow(() -> Email.valueOf(maxEmail));
    }

    @Test
    void username_shouldHandleSpecialCharactersBoundary() {
        // Act & Assert - Test edge cases of allowed characters
        assertDoesNotThrow(() -> Username.valueOf("a_b"));
        assertDoesNotThrow(() -> Username.valueOf("a-b"));
        assertDoesNotThrow(() -> Username.valueOf("a.b"));
        assertDoesNotThrow(() -> Username.valueOf("123"));
    }

    @Test
    void password_shouldHandleSpecialCharacters() {
        // Act & Assert - Passwords with special characters
        assertDoesNotThrow(() -> Password.valueOf("P@ssw0rd!", passwordEncoder));
        assertDoesNotThrow(() -> Password.valueOf("🔒secure🔑", passwordEncoder));
    }

    @Test
    void user_shouldHandleNullRolesGracefully() {
        // Arrange
        Username username = Username.valueOf("testuser");
        Email email = Email.valueOf("test@example.com");
        Password password = Password.valueOf("password123", passwordEncoder);
        User user = new User(username, email, password);

        // Act & Assert - Should handle no roles gracefully
        assertNotNull(user.getAuthorities());
        assertTrue(user.getAuthorities().isEmpty());
        assertNotNull(user.getRoles());
        assertTrue(user.getRoles().isEmpty());
    }

    @Test
    void user_shouldPreventDuplicateRoles() {
        // Arrange
        Username username = Username.valueOf("testuser");
        Email email = Email.valueOf("test@example.com");
        Password password = Password.valueOf("password123", passwordEncoder);
        User user = new User(username, email, password);

        // Act - Add same role twice
        user.addRole(AppRole.USER);
        user.addRole(AppRole.USER);

        // Assert - Should only have one instance
        assertEquals(1, user.getRoles().size());
        assertTrue(user.getRoles().contains(AppRole.USER));
    }

    @Test
    void password_shouldMatchCorrectly() {
        // Arrange
        String plainPassword = "testPassword123";
        Password password = Password.valueOf(plainPassword, passwordEncoder);

        // Act & Assert
        assertTrue(password.matches(plainPassword, passwordEncoder));
        assertFalse(password.matches("wrongPassword", passwordEncoder));
    }

    @Test
    void password_shouldRejectNullRawPasswordInMatches() {
        // Arrange
        Password password = Password.valueOf("testPassword123", passwordEncoder);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, 
            () -> password.matches(null, passwordEncoder));
        assertEquals("Raw password cannot be null or blank", exception.getMessage());
    }
}
