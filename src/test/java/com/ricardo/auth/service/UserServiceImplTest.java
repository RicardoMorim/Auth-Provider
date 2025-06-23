package com.ricardo.auth.service;

import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.*;
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

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        
        // Create a test user
        Username username = Username.valueOf("existinguser");
        Email email = Email.valueOf("existing@example.com");
        Password password = Password.valueOf("password123", passwordEncoder);
        testUser = new User(username, email, password);
        userRepository.save(testUser);
    }    @Test
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

    @Test
    void getUserById_shouldReturnUser_whenUserExists() {
        // Act
        User foundUser = userService.getUserById(testUser.getId());

        // Assert
        assertNotNull(foundUser);
        assertEquals(testUser.getId(), foundUser.getId());
        assertEquals("existing@example.com", foundUser.getEmail());
    }

    @Test
    void getUserById_shouldThrowResourceNotFoundException_whenUserDoesNotExist() {
        // Act & Assert
        assertThrows(ResourceNotFoundException.class, () -> {
            userService.getUserById(999L);
        });
    }

    @Test
    void getUserByEmail_shouldReturnUser_whenEmailExists() {
        // Act
        User foundUser = userService.getUserByEmail("existing@example.com");

        // Assert
        assertNotNull(foundUser);
        assertEquals("existing@example.com", foundUser.getEmail());
        assertEquals("existinguser", foundUser.getUsername());
    }

    @Test
    void getUserByEmail_shouldThrowResourceNotFoundException_whenEmailDoesNotExist() {
        // Act & Assert
        assertThrows(ResourceNotFoundException.class, () -> {
            userService.getUserByEmail("nonexistent@example.com");
        });
    }

    @Test
    void userExists_shouldReturnTrue_whenEmailExists() {
        // Act
        boolean exists = userService.userExists("existing@example.com");

        // Assert
        assertTrue(exists);
    }

    @Test
    void userExists_shouldReturnFalse_whenEmailDoesNotExist() {
        // Act
        boolean exists = userService.userExists("nonexistent@example.com");

        // Assert
        assertFalse(exists);
    }    @Test
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

    @Test
    void deleteUser_shouldDeleteUser_whenUserExists() {
        // Act
        userService.deleteUser(testUser.getId());

        // Assert
        assertFalse(userRepository.existsById(testUser.getId()));
    }

    @Test
    void deleteUser_shouldThrowResourceNotFoundException_whenUserDoesNotExist() {
        // Act & Assert
        assertThrows(ResourceNotFoundException.class, () -> {
            userService.deleteUser(999L);
        });
    }    @Test
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
