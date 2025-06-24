package com.ricardo.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ricardo.auth.domain.Email;
import com.ricardo.auth.domain.Password;
import com.ricardo.auth.domain.User;
import com.ricardo.auth.domain.Username;
import com.ricardo.auth.dto.LoginRequestDTO;
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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The type Auth controller test.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;    @Autowired
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

        // Create a test user with encoded password
        Username username = Username.valueOf("testuser");
        Email email = Email.valueOf("test@example.com");
        Password password = Password.fromHash(passwordEncoder.encode("password123"));
        testUser = new User(username, email, password);
        userRepository.save(testUser);
    }

    /**
     * Login should return token when credentials are valid.
     *
     * @throws Exception the exception
     */
    @Test
    void login_shouldReturnToken_whenCredentialsAreValid() throws Exception {
        // Arrange
        LoginRequestDTO request = new LoginRequestDTO("test@example.com", "password123");

        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.token").isNotEmpty());
    }

    /**
     * Login should return 401 when credentials are invalid.
     *
     * @throws Exception the exception
     */
    @Test
    void login_shouldReturn401_whenCredentialsAreInvalid() throws Exception {
        // Arrange
        LoginRequestDTO request = new LoginRequestDTO("test@example.com", "wrongpassword");

        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Login should return 401 when user does not exist.
     *
     * @throws Exception the exception
     */
    @Test
    void login_shouldReturn401_whenUserDoesNotExist() throws Exception {
        // Arrange
        LoginRequestDTO request = new LoginRequestDTO("nonexistent@example.com", "password123");

        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Gets authenticated user should return user details when token is valid.
     *
     * @throws Exception the exception
     */
    @Test
    void getAuthenticatedUser_shouldReturnUserDetails_whenTokenIsValid() throws Exception {
        // First, login to get a token
        LoginRequestDTO loginRequest = new LoginRequestDTO("test@example.com", "password123");

        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        // Extract token from response (you might need to parse JSON)
        String token = extractTokenFromResponse(response);

        // Use token to access protected endpoint
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("testuser"));
    }

    /**
     * Gets authenticated user should return 401 when no token provided.
     *
     * @throws Exception the exception
     */
    @Test
    void getAuthenticatedUser_shouldReturn401_whenNoTokenProvided() throws Exception {
        // Act & Assert
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Gets authenticated user should return 401 when token is invalid.
     *
     * @throws Exception the exception
     */
    @Test
    void getAuthenticatedUser_shouldReturn401_whenTokenIsInvalid() throws Exception {
        // Act & Assert
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer invalid.jwt.token"))
                .andExpect(status().isUnauthorized());
    }

    private String extractTokenFromResponse(String response) throws Exception {
        // Parse JSON response to extract token
        return objectMapper.readTree(response).get("token").asText();
    }
}