package com.ricardo.auth.service;

import com.ricardo.auth.domain.Email;
import com.ricardo.auth.domain.Password;
import com.ricardo.auth.domain.User;
import com.ricardo.auth.domain.Username;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import com.ricardo.auth.repository.UserJpaRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for UserDetailsServiceImpl.
 * Tests Spring Security integration and user loading functionality.
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class UserDetailsServiceImplTest {

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private UserJpaRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private User testUser;

    /**
     * Sets up.
     */
    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        
        // Create and save test user
        testUser = new User(
            Username.valueOf("testuser"),
            Email.valueOf("test@example.com"),
            Password.valueOf("password123", passwordEncoder)
        );
        testUser = userRepository.save(testUser);
    }

    // ========== SUCCESSFUL USER LOADING TESTS ==========

    /**
     * Load user by username should return user details for valid email.
     */
    @Test
    void loadUserByUsername_shouldReturnUserDetailsForValidEmail() {
        // Act
        UserDetails userDetails = userDetailsService.loadUserByUsername("test@example.com");

        // Assert
        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
        assertTrue(passwordEncoder.matches("password123", userDetails.getPassword()));
        assertNotNull(userDetails.getAuthorities());
    }

    /**
     * Load user by username should return correct authorities.
     */
    @Test
    void loadUserByUsername_shouldReturnCorrectAuthorities() {
        // Arrange - Add roles to user
        testUser.addRole(com.ricardo.auth.domain.AppRole.USER);
        testUser.addRole(com.ricardo.auth.domain.AppRole.ADMIN);
        userRepository.save(testUser);

        // Act
        UserDetails userDetails = userDetailsService.loadUserByUsername("test@example.com");

        // Assert
        assertNotNull(userDetails.getAuthorities());
        assertEquals(2, userDetails.getAuthorities().size());
        
        boolean hasUserRole = userDetails.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals("ROLE_USER"));
        boolean hasAdminRole = userDetails.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
        
        assertTrue(hasUserRole);
        assertTrue(hasAdminRole);
    }

    /**
     * Load user by username should return user with correct account status.
     */
    @Test
    void loadUserByUsername_shouldReturnUserWithCorrectAccountStatus() {
        // Act
        UserDetails userDetails = userDetailsService.loadUserByUsername("test@example.com");

        // Assert - Test UserDetails interface methods
        assertTrue(userDetails.isAccountNonExpired());
        assertTrue(userDetails.isAccountNonLocked());
        assertTrue(userDetails.isCredentialsNonExpired());
        assertTrue(userDetails.isEnabled());
    }

    // ========== USER NOT FOUND TESTS ==========

    /**
     * Load user by username should throw exception for non existent email.
     */
    @Test
    void loadUserByUsername_shouldThrowExceptionForNonExistentEmail() {
        // Act & Assert
        assertThrows(ResourceNotFoundException.class, () -> {
            userDetailsService.loadUserByUsername("nonexistent@example.com");
        });
    }

    /**
     * Load user by username should throw exception for null email.
     */
    @Test
    void loadUserByUsername_shouldThrowExceptionForNullEmail() {
        // Act & Assert
        assertThrows(ResourceNotFoundException.class, () -> {
            userDetailsService.loadUserByUsername(null);
        });
    }

    /**
     * Load user by username should throw exception for empty email.
     */
    @Test
    void loadUserByUsername_shouldThrowExceptionForEmptyEmail() {
        // Act & Assert
        assertThrows(ResourceNotFoundException.class, () -> {
            userDetailsService.loadUserByUsername("");
        });

        assertThrows(ResourceNotFoundException.class, () -> {
            userDetailsService.loadUserByUsername("   ");
        });
    }

    // ========== CASE SENSITIVITY TESTS ==========

    /**
     * Load user by username should be case sensitive.
     */
    @Test
    void loadUserByUsername_shouldBeCaseSensitive() {
        // Act & Assert - Email should be case sensitive
        assertThrows(ResourceNotFoundException.class, () -> {
            userDetailsService.loadUserByUsername("TEST@EXAMPLE.COM");
        });

        assertThrows(ResourceNotFoundException.class, () -> {
            userDetailsService.loadUserByUsername("Test@Example.Com");
        });
    }

    // ========== MULTIPLE USERS TESTS ==========

    /**
     * Load user by username should load correct user when multiple exist.
     */
    @Test
    void loadUserByUsername_shouldLoadCorrectUserWhenMultipleExist() {
        // Arrange - Create additional users
        User user2 = new User(
            Username.valueOf("user2"),
            Email.valueOf("user2@example.com"),
            Password.valueOf("password456", passwordEncoder)
        );
        user2.addRole(com.ricardo.auth.domain.AppRole.ADMIN);
        userRepository.save(user2);

        User user3 = new User(
            Username.valueOf("user3"),
            Email.valueOf("user3@example.com"),
            Password.valueOf("password789", passwordEncoder)
        );
        userRepository.save(user3);

        // Act
        UserDetails userDetails1 = userDetailsService.loadUserByUsername("test@example.com");
        UserDetails userDetails2 = userDetailsService.loadUserByUsername("user2@example.com");
        UserDetails userDetails3 = userDetailsService.loadUserByUsername("user3@example.com");

        // Assert
        assertEquals("testuser", userDetails1.getUsername());
        assertEquals("user2", userDetails2.getUsername());
        assertEquals("user3", userDetails3.getUsername());

        // Verify passwords
        assertTrue(passwordEncoder.matches("password123", userDetails1.getPassword()));
        assertTrue(passwordEncoder.matches("password456", userDetails2.getPassword()));
        assertTrue(passwordEncoder.matches("password789", userDetails3.getPassword()));
    }

    // ========== USER WITH NO ROLES TESTS ==========

    /**
     * Load user by username should handle user with no roles.
     */
    @Test
    void loadUserByUsername_shouldHandleUserWithNoRoles() {
        // Act - testUser has no roles by default
        UserDetails userDetails = userDetailsService.loadUserByUsername("test@example.com");

        // Assert
        assertNotNull(userDetails);
        assertNotNull(userDetails.getAuthorities());
        assertTrue(userDetails.getAuthorities().isEmpty());
    }

    // ========== SPECIAL CHARACTER TESTS ==========

    /**
     * Load user by username should handle emails with special characters.
     */
    @Test
    void loadUserByUsername_shouldHandleEmailsWithSpecialCharacters() {
        // Arrange - Create user with special characters in email
        User specialUser = new User(
            Username.valueOf("specialuser"),
            Email.valueOf("test+tag@example.com"),
            Password.valueOf("password123", passwordEncoder)
        );
        userRepository.save(specialUser);

        // Act
        UserDetails userDetails = userDetailsService.loadUserByUsername("test+tag@example.com");

        // Assert
        assertNotNull(userDetails);
        assertEquals("specialuser", userDetails.getUsername());
    }

    // ========== WHITESPACE HANDLING TESTS ==========

    /**
     * Load user by username should handle whitespace in email.
     */
    @Test
    void loadUserByUsername_shouldHandleWhitespaceInEmail() {
        // Act & Assert - Should not find user with whitespace
        assertThrows(ResourceNotFoundException.class, () -> {
            userDetailsService.loadUserByUsername(" test@example.com ");
        });

        assertThrows(ResourceNotFoundException.class, () -> {
            userDetailsService.loadUserByUsername("test@example.com ");
        });

        assertThrows(ResourceNotFoundException.class, () -> {
            userDetailsService.loadUserByUsername(" test@example.com");
        });
    }

    // ========== PERFORMANCE TESTS ==========

    /**
     * Load user by username should load user quickly.
     */
    @Test
    void loadUserByUsername_shouldLoadUserQuickly() {
        // This test ensures the service performs well
        long startTime = System.currentTimeMillis();

        // Act
        UserDetails userDetails = userDetailsService.loadUserByUsername("test@example.com");

        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;

        // Assert
        assertNotNull(userDetails);
        assertTrue(duration < 1000, "User loading should complete within 1 second"); // Performance check
    }

    /**
     * Load user by username should handle multiple consecutive calls.
     */
    @Test
    void loadUserByUsername_shouldHandleMultipleConsecutiveCalls() {
        // Act - Call multiple times to ensure no state issues
        UserDetails userDetails1 = userDetailsService.loadUserByUsername("test@example.com");
        UserDetails userDetails2 = userDetailsService.loadUserByUsername("test@example.com");
        UserDetails userDetails3 = userDetailsService.loadUserByUsername("test@example.com");

        // Assert - All calls should return equivalent UserDetails
        assertEquals(userDetails1.getUsername(), userDetails2.getUsername());
        assertEquals(userDetails2.getUsername(), userDetails3.getUsername());
        assertEquals(userDetails1.getPassword(), userDetails2.getPassword());
        assertEquals(userDetails2.getPassword(), userDetails3.getPassword());
    }

    // ========== ERROR MESSAGE TESTS ==========

    /**
     * Load user by username should provide informative error message.
     */
    @Test
    void loadUserByUsername_shouldProvideInformativeErrorMessage() {
        // Act & Assert
        ResourceNotFoundException exception = assertThrows(ResourceNotFoundException.class, () -> {
            userDetailsService.loadUserByUsername("nonexistent@example.com");
        });

        // Verify error message is informative
        assertNotNull(exception.getMessage());
        assertFalse(exception.getMessage().isEmpty());
        assertTrue(exception.getMessage().contains("nonexistent@example.com"));
    }

    // ========== INTEGRATION WITH REPOSITORY TESTS ==========

    /**
     * Load user by username should reflect database changes.
     */
    @Test
    void loadUserByUsername_shouldReflectDatabaseChanges() {
        // Arrange - Load user initially
        UserDetails initialUserDetails = userDetailsService.loadUserByUsername("test@example.com");
        assertTrue(initialUserDetails.getAuthorities().isEmpty());

        // Act - Modify user in database
        testUser.addRole(com.ricardo.auth.domain.AppRole.USER);
        userRepository.save(testUser);

        // Load user again
        UserDetails updatedUserDetails = userDetailsService.loadUserByUsername("test@example.com");

        // Assert - Should reflect database changes
        assertEquals(1, updatedUserDetails.getAuthorities().size());
        assertTrue(updatedUserDetails.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals("ROLE_USER")));
    }

    // ========== TRANSACTIONAL BEHAVIOR TESTS ==========

    /**
     * Load user by username should work within transaction.
     */
    @Test
    void loadUserByUsername_shouldWorkWithinTransaction() {
        // This test ensures the service works correctly within Spring transactions
        
        // Act & Assert - Should work normally within @Transactional test
        assertDoesNotThrow(() -> {
            UserDetails userDetails = userDetailsService.loadUserByUsername("test@example.com");
            assertNotNull(userDetails);
        });
    }
}
