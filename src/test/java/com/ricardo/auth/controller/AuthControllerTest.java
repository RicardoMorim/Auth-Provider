package com.ricardo.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.user.*;
import com.ricardo.auth.dto.LoginRequestDTO;
import com.ricardo.auth.repository.user.UserRepository;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

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
    private ObjectMapper objectMapper;
    @Autowired
    private UserRepository<User, AppRole, UUID> userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private User testUser;
    @Autowired
    private UserService<User, AppRole, UUID> userService;

    /**
     * Sets up.
     */
    @BeforeEach
    void setUp() {
        userService.deleteAllUsers();

        // Create a test user with encoded password
        Username username = Username.valueOf("testuser");
        Email email = Email.valueOf("test@example.com");
        Password password = Password.fromHash(passwordEncoder.encode("Password123"));
        testUser = new User(username, email, password);
        userService.createUser(testUser);
    }

    /**
     * Login should return token when credentials are valid.
     *
     * @throws Exception the exception
     */
    @Test
    void login_shouldReturnToken_whenCredentialsAreValid() throws Exception {
        // Arrange
        LoginRequestDTO request = new LoginRequestDTO("test@example.com", "Password123");

        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("access_token"))
                .andExpect(cookie().exists("refresh_token"));
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
        LoginRequestDTO request = new LoginRequestDTO("nonexistent@example.com", "Password123");

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
        // First, login to get cookies
        LoginRequestDTO loginRequest = new LoginRequestDTO("test@example.com", "Password123");
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        Cookie accessTokenCookie = loginResult.getResponse().getCookie("access_token");

        // Use cookie to access protected endpoint
        mockMvc.perform(get("/api/auth/me").with(csrf())
                        .cookie(accessTokenCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("test@example.com"));
    }

    /**
     * Gets authenticated user should return 401 when no token provided.
     *
     * @throws Exception the exception
     */
    @Test
    void getAuthenticatedUser_shouldReturn401_whenNoTokenProvided() throws Exception {
        // Act & Assert
        mockMvc.perform(get("/api/auth/me").with(csrf()))
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
        mockMvc.perform(get("/api/auth/me").with(csrf())
                        .cookie(new Cookie("access_token", "Bearer invalid.jwt.token")))
                .andExpect(status().isUnauthorized());
    }
}