package com.ricardo.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ricardo.auth.domain.user.Email;
import com.ricardo.auth.domain.user.Password;
import com.ricardo.auth.domain.user.User;
import com.ricardo.auth.domain.user.Username;
import com.ricardo.auth.dto.LoginRequestDTO;
import com.ricardo.auth.repository.user.DefaultUserJpaRepository;
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
    private DefaultUserJpaRepository userRepository;

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
        // First, login to get cookies
        LoginRequestDTO loginRequest = new LoginRequestDTO("test@example.com", "password123");
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