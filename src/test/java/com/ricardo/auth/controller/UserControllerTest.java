package com.ricardo.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ricardo.auth.domain.*;
import com.ricardo.auth.dto.CreateUserRequestDTO;
import com.ricardo.auth.repository.UserJpaRepository;
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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

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
    private UserJpaRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    @Test
    void createUser_shouldReturn201_whenRequestIsValid() throws Exception {
        // Arrange
        CreateUserRequestDTO request = new CreateUserRequestDTO("newUser", "new@example.com", "password123");

        // Act & Assert
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value(request.getUsername()))
                .andExpect(jsonPath("$.email").value(request.getEmail()));
        
        // Verify user was actually created in database
        assertTrue(userRepository.existsByEmail("new@example.com"));
    }

    @Test
    void createUser_shouldReturn409_whenEmailAlreadyExists() throws Exception {
        // Arrange - Create existing user
        Username username = Username.valueOf("existinguser");
        Email email = Email.valueOf("existing@example.com");
        Password password = Password.valueOf("password123", passwordEncoder);
        User existingUser = new User(username, email, password);
        userRepository.save(existingUser);

        CreateUserRequestDTO request = new CreateUserRequestDTO("newUser", "existing@example.com", "password123");

        // Act & Assert
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Email already exists: existing@example.com"));
    }

    @Test
    void createUser_shouldReturn400_whenUsernameIsEmpty() throws Exception {
        // Arrange
        CreateUserRequestDTO request = new CreateUserRequestDTO("", "new@example.com", "password123");

        // Act & Assert
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void createUser_shouldReturn400_whenEmailIsEmpty() throws Exception {
        // Arrange
        CreateUserRequestDTO request = new CreateUserRequestDTO("newUser", "", "password123");

        // Act & Assert
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void createUser_shouldReturn400_whenPasswordIsEmpty() throws Exception {
        // Arrange
        CreateUserRequestDTO request = new CreateUserRequestDTO("newUser", "new@example.com", "");

        // Act & Assert
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void createUser_shouldReturn400_whenEmailIsInvalid() throws Exception {
        // Arrange
        CreateUserRequestDTO request = new CreateUserRequestDTO("newUser", "invalid-email", "password123");

        // Act & Assert
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }
}
