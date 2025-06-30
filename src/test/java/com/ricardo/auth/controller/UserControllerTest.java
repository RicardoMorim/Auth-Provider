package com.ricardo.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.User;
import com.ricardo.auth.dto.CreateUserRequestDTO;
import com.ricardo.auth.repository.DefaultUserJpaRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for UserController.
 * Tests the full request-response cycle including validation, service calls, and error handling.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserService<User, Long> userService;

    @Autowired
    private DefaultUserJpaRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private PasswordPolicyService passwordPolicyService;

    @Autowired
    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        // Clean database before each test
        userRepository.deleteAll();
    }

    @Test
    void createUser_shouldReturn201_whenRequestIsValid() throws Exception {
        // Arrange
        CreateUserRequestDTO request = new CreateUserRequestDTO("newUser", "new@example.com", "Password@123");

        // Act & Assert - Test with real service
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value(request.getUsername()))
                .andExpect(jsonPath("$.email").value(request.getEmail()))
                .andExpect(jsonPath("$.id").exists());

        // Verify user was actually created in database
        assertTrue(userRepository.existsByEmail_Email("new@example.com"));
        User createdUser = userRepository.findByEmail_Email("new@example.com").orElseThrow();
        assertEquals("newUser", createdUser.getUsername());
    }

    @Test
    void createUser_shouldReturn409_whenEmailAlreadyExists() throws Exception {
        // Arrange - Create user first
        CreateUserRequestDTO firstRequest = new CreateUserRequestDTO("existingUser", "existing@example.com", "Password@123");

        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(firstRequest)))
                .andExpect(status().isCreated());

        // Try to create user with same email
        CreateUserRequestDTO duplicateRequest = new CreateUserRequestDTO("anotherUser", "existing@example.com", "Password@456");

        // Act & Assert
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(duplicateRequest)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Email already exists: existing@example.com"));

        // Verify only one user exists
        assertEquals(1, userRepository.count());
    }

    @Test
    void createUser_shouldReturn400_whenRequestIsInvalid() throws Exception {
        // Arrange - Invalid request data
        CreateUserRequestDTO invalidRequest = new CreateUserRequestDTO("", "invalid-email", "123");

        // Act & Assert
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());

        // Verify no user was created
        assertEquals(0, userRepository.count());
    }

    @Test
    void createUser_shouldReturn400_whenPasswordPolicyViolated() throws Exception {
        // Arrange - Password that violates policy (too short, based on your test config)
        CreateUserRequestDTO request = new CreateUserRequestDTO("testUser", "test@example.com", "weak");

        // Act & Assert
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());

        // Verify no user was created
        assertEquals(0, userRepository.count());
    }

    @Test
    void createUser_shouldHashPasswordCorrectly() throws Exception {
        // Arrange
        CreateUserRequestDTO request = new CreateUserRequestDTO("testUser", "test@example.com", "Password@123");

        // Act
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());

        // Assert - Password should be hashed
        User createdUser = userRepository.findByEmail_Email("test@example.com").orElseThrow();
        assertNotEquals("Password@123", createdUser.getPassword()); // Should be hashed
        assertTrue(passwordEncoder.matches("Password@123", createdUser.getPassword())); // But should match when decoded
    }
}