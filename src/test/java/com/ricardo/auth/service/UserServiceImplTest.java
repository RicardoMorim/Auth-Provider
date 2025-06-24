package com.ricardo.auth.service;

import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.Email;
import com.ricardo.auth.domain.Password;
import com.ricardo.auth.domain.User;
import com.ricardo.auth.domain.Username;
import com.ricardo.auth.domain.exceptions.DuplicateResourceException;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import com.ricardo.auth.repository.UserJpaRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The type User service impl test.
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class UserServiceImplTest {

    @Autowired
    private UserService<User, Long> userService;

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
        
        // Create a test user
        Username username = Username.valueOf("existinguser");
        Email email = Email.valueOf("existing@example.com");
        Password password = Password.valueOf("password123", passwordEncoder);
        testUser = new User(username, email, password);
        userRepository.save(testUser);
    }

    /**
     * Create user should save and return user when email does not exist.
     */
    @Test
    void createUser_shouldSaveAndReturnUser_whenEmailDoesNotExist() {
        // Arrange
        Username username = Username.valueOf("newuser");
        Email email = Email.valueOf("new@example.com");
        Password password = Password.valueOf("password123", passwordEncoder);
        User newUser = new User(username, email, password);

        // Act
        User createdUser = userService.createUser(newUser);

        // Assert
        assertNotNull(createdUser);
        assertNotNull(createdUser.getId());
        assertEquals("new@example.com", createdUser.getEmail());
        assertTrue(userRepository.existsByEmail("new@example.com"));
    }

    /**
     * Create user should throw duplicate resource exception when email exists.
     */
    @Test
    void createUser_shouldThrowDuplicateResourceException_whenEmailExists() {
        // Arrange
        Username username = Username.valueOf("anotheruser");
        Email email = Email.valueOf("existing@example.com"); // Same email as setup
        Password password = Password.valueOf("password123", passwordEncoder);
        User duplicateUser = new User(username, email, password);

        // Act & Assert
        Exception exception = assertThrows(DuplicateResourceException.class, () -> {
            userService.createUser(duplicateUser);
        });
        assertEquals("Email already exists: existing@example.com", exception.getMessage());
    }

    /**
     * Gets user by id should return user when user exists.
     */
    @Test
    void getUserById_shouldReturnUser_whenUserExists() {
        // Act
        User foundUser = userService.getUserById(testUser.getId());

        // Assert
        assertNotNull(foundUser);
        assertEquals(testUser.getId(), foundUser.getId());
        assertEquals("existing@example.com", foundUser.getEmail());
    }

    /**
     * Gets user by id should throw resource not found exception when user does not exist.
     */
    @Test
    void getUserById_shouldThrowResourceNotFoundException_whenUserDoesNotExist() {
        // Act & Assert
        assertThrows(ResourceNotFoundException.class, () -> {
            userService.getUserById(999L);
        });
    }

    /**
     * Gets user by email should return user when email exists.
     */
    @Test
    void getUserByEmail_shouldReturnUser_whenEmailExists() {
        // Act
        User foundUser = userService.getUserByEmail("existing@example.com");

        // Assert
        assertNotNull(foundUser);
        assertEquals("existing@example.com", foundUser.getEmail());
        assertEquals("existinguser", foundUser.getUsername());
    }

    /**
     * Gets user by email should throw resource not found exception when email does not exist.
     */
    @Test
    void getUserByEmail_shouldThrowResourceNotFoundException_whenEmailDoesNotExist() {
        // Act & Assert
        assertThrows(ResourceNotFoundException.class, () -> {
            userService.getUserByEmail("nonexistent@example.com");
        });
    }

    /**
     * User exists should return true when email exists.
     */
    @Test
    void userExists_shouldReturnTrue_whenEmailExists() {
        // Act
        boolean exists = userService.userExists("existing@example.com");

        // Assert
        assertTrue(exists);
    }

    /**
     * User exists should return false when email does not exist.
     */
    @Test
    void userExists_shouldReturnFalse_whenEmailDoesNotExist() {
        // Act
        boolean exists = userService.userExists("nonexistent@example.com");

        // Assert
        assertFalse(exists);
    }

    /**
     * Update user should update user details.
     */
    @Test
    void updateUser_shouldUpdateUserDetails() {
        // Arrange
        Username newUsername = Username.valueOf("updateduser");
        Email newEmail = Email.valueOf("updated@example.com");
        Password newPassword = Password.valueOf("newpassword123", passwordEncoder);
        User userDetails = new User(newUsername, newEmail, newPassword);

        // Act
        User updatedUser = userService.updateUser(testUser.getId(), userDetails);

        // Assert
        assertNotNull(updatedUser);
        assertEquals(testUser.getId(), updatedUser.getId());
        assertEquals("updateduser", updatedUser.getUsername());
        assertEquals("updated@example.com", updatedUser.getEmail());
    }

    /**
     * Delete user should delete user when user exists.
     */
    @Test
    void deleteUser_shouldDeleteUser_whenUserExists() {
        // Act
        userService.deleteUser(testUser.getId());

        // Assert
        assertFalse(userRepository.existsById(testUser.getId()));
    }

    /**
     * Delete user should throw resource not found exception when user does not exist.
     */
    @Test
    void deleteUser_shouldThrowResourceNotFoundException_whenUserDoesNotExist() {
        // Act & Assert
        assertThrows(ResourceNotFoundException.class, () -> {
            userService.deleteUser(999L);
        });
    }

    /**
     * Gets all users should return all users.
     */
    @Test
    void getAllUsers_shouldReturnAllUsers() {
        // Arrange - Add another user
        Username username = Username.valueOf("seconduser");
        Email email = Email.valueOf("second@example.com");
        Password password = Password.valueOf("password123", passwordEncoder);
        User secondUser = new User(username, email, password);
        userRepository.save(secondUser);

        // Act
        List<User> users = userService.getAllUsers();

        // Assert
        assertEquals(2, users.size());
    }
}
