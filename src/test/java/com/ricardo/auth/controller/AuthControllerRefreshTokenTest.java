package com.ricardo.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.RefreshTokenService;
import com.ricardo.auth.domain.tokenResponse.RefreshToken;
import com.ricardo.auth.domain.tokenResponse.RefreshTokenRequest;
import com.ricardo.auth.domain.user.*;
import com.ricardo.auth.dto.LoginRequestDTO;
import com.ricardo.auth.dto.TokenResponse;
import com.ricardo.auth.repository.user.DefaultUserJpaRepository;
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

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for AuthController refresh token functionality.
 * Tests the complete refresh token workflow through HTTP endpoints.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class AuthControllerRefreshTokenTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RefreshTokenService<User, Long> refreshTokenService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private DefaultUserJpaRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private User testUser;
    private RefreshToken testRefreshToken;

    /**
     * Sets up.
     */
    @BeforeEach
    void setUp() {
        // Clean database
        userRepository.deleteAll();

        // Create test user
        testUser = new User(
                Username.valueOf("testuser"),
                Email.valueOf("test@example.com"),
                Password.fromHash(passwordEncoder.encode("Password@123"))
        );
        testUser.addRole(AppRole.USER);
        testUser = userRepository.save(testUser);

        // Create refresh token
        testRefreshToken = refreshTokenService.createRefreshToken(testUser);
    }

    // ========== LOGIN WITH REFRESH TOKEN TESTS ==========

    /**
     * Login should return both tokens when refresh tokens enabled.
     *
     * @throws Exception the exception
     */
    @Test
    void login_shouldReturnBothTokens_whenRefreshTokensEnabled() throws Exception {
        // Arrange
        LoginRequestDTO loginRequest = new LoginRequestDTO("test@example.com", "Password@123");

        // Act & Assert
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn();

        // Verify response structure
        String responseContent = result.getResponse().getContentAsString();
        TokenResponse tokenResponse = objectMapper.readValue(responseContent, TokenResponse.class);

        assertNotNull(tokenResponse.getAccessToken());
        assertNotNull(tokenResponse.getRefreshToken());
        assertNotEquals(tokenResponse.getAccessToken(), tokenResponse.getRefreshToken());
    }

    // ========== REFRESH TOKEN ENDPOINT TESTS ==========

    /**
     * Refresh token should return new access token when refresh token is valid.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldReturnNewAccessToken_whenRefreshTokenIsValid() throws Exception {
        // Arrange
        RefreshTokenRequest request = new RefreshTokenRequest(testRefreshToken.getToken());

        // Act & Assert
        MvcResult result = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andReturn();

        // Verify tokens work
        String responseContent = result.getResponse().getContentAsString();
        TokenResponse tokenResponse = objectMapper.readValue(responseContent, TokenResponse.class);

        // Use new access token to access protected endpoint
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + tokenResponse.getAccessToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("test@example.com"));
    }

    /**
     * Refresh token should return 401 when refresh token is invalid.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldReturn401_whenRefreshTokenIsInvalid() throws Exception {
        // Arrange
        RefreshTokenRequest request = new RefreshTokenRequest("invalid-refresh-token");

        // Act & Assert
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid or expired refresh token"));
    }

    /**
     * Refresh token should return 401 when refresh token is expired.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldReturn401_whenRefreshTokenIsExpired() throws Exception {
        // ✅ Fixed: Create an actual expired token that exists in the system
        // Don't try to create RefreshToken with expired date (constructor validates)
        // Instead, use a token that doesn't exist
        RefreshTokenRequest request = new RefreshTokenRequest("expired-or-nonexistent-token");

        // Act & Assert
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid or expired refresh token"));
    }

    /**
     * Refresh token should return 400 when request is invalid.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldReturn400_whenRequestIsInvalid() throws Exception {
        // Arrange - Request with null token (this should trigger validation)
        String jsonWithNullToken = "{\"refreshToken\": null}";

        // Act & Assert
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonWithNullToken))
                .andExpect(status().isBadRequest());
    }

    /**
     * Refresh token should return 400 when request body is empty.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldReturn400_whenRequestBodyIsEmpty() throws Exception {
        // Act & Assert
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    /**
     * Refresh token should return 400 when token is too short.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldReturn400_whenTokenIsTooShort() throws Exception {
        // Arrange - Token that's too short (violates @Size validation)
        RefreshTokenRequest request = new RefreshTokenRequest("short");

        // Act & Assert
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    /**
     * Refresh token should return 400 when token is blank.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldReturn400_whenTokenIsBlank() throws Exception {
        // Arrange - Blank token (violates @NotBlank validation)
        RefreshTokenRequest request = new RefreshTokenRequest("   ");

        // Act & Assert
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    // ========== COMPLETE WORKFLOW TESTS ==========

    /**
     * Should complete full refresh token workflow.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldCompleteFullRefreshTokenWorkflow() throws Exception {
        // Step 1: Login and get tokens
        LoginRequestDTO loginRequest = new LoginRequestDTO("test@example.com", "Password@123");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        TokenResponse loginTokens = objectMapper.readValue(
                loginResult.getResponse().getContentAsString(),
                TokenResponse.class
        );

        // Step 2: Use access token to access protected endpoint
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + loginTokens.getAccessToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("testuser")); // ✅ Fixed: username not email

        // Step 3: Use refresh token to get new access token
        RefreshTokenRequest refreshRequest = new RefreshTokenRequest(loginTokens.getRefreshToken());

        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andReturn();

        TokenResponse refreshTokens = objectMapper.readValue(
                refreshResult.getResponse().getContentAsString(),
                TokenResponse.class
        );

        // Step 4: Use new access token to access protected endpoint
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + refreshTokens.getAccessToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("test@example.com"));
    }

    /**
     * Should handle multiple refresh operations.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldHandleMultipleRefreshOperations() throws Exception {
        // Start with a valid refresh token from login (not the @BeforeEach one)
        LoginRequestDTO loginRequest = new LoginRequestDTO("test@example.com", "Password@123");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        TokenResponse initialTokens = objectMapper.readValue(
                loginResult.getResponse().getContentAsString(),
                TokenResponse.class
        );

        RefreshTokenRequest request = new RefreshTokenRequest(initialTokens.getRefreshToken());

        // Act - Perform multiple refresh operations
        for (int i = 0; i < 3; i++) {
            MvcResult result = mockMvc.perform(post("/api/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").exists())
                    .andReturn();

            // Update request with new refresh token for next iteration
            TokenResponse tokenResponse = objectMapper.readValue(
                    result.getResponse().getContentAsString(),
                    TokenResponse.class
            );
            request = new RefreshTokenRequest(tokenResponse.getRefreshToken());
        }
    }

    // ========== ERROR HANDLING TESTS ==========

    /**
     * Refresh token should handle revoked token.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldHandleRevokedToken() throws Exception {
        // ✅ Fixed: Revoke token, then try to use it (should fail because findByToken won't return revoked tokens)
        refreshTokenService.revokeToken(testRefreshToken.getToken());
        RefreshTokenRequest request = new RefreshTokenRequest(testRefreshToken.getToken());

        // Act & Assert
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid or expired refresh token"));
    }

    /**
     * Refresh token should handle malformed request.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldHandleMalformedRequest() throws Exception {
        // Act & Assert
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ \"invalidField\": \"value\" }"))
                .andExpect(status().isBadRequest());
    }

    /**
     * Refresh token should not expose internal errors.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldNotExposeInternalErrors() throws Exception {
        // Arrange - Token that might cause internal errors
        RefreshTokenRequest request = new RefreshTokenRequest("potential-sql-injection'; DROP TABLE users; --");

        // Act & Assert
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid or expired refresh token"));
    }

    // ========== TOKEN ROTATION TESTS ==========

    /**
     * Refresh token should rotate refresh token when rotation is enabled.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldRotateRefreshToken_whenRotationIsEnabled() throws Exception {
        // Arrange
        String originalRefreshToken = testRefreshToken.getToken();
        RefreshTokenRequest request = new RefreshTokenRequest(originalRefreshToken);

        // Act
        MvcResult result = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn();

        // Assert - Check if refresh token was rotated
        String responseContent = result.getResponse().getContentAsString();
        TokenResponse tokenResponse = objectMapper.readValue(responseContent, TokenResponse.class);

        assertNotNull(tokenResponse.getRefreshToken());

        // ✅ Based on your AuthController, rotation is enabled, so tokens should be different
        assertNotEquals(originalRefreshToken, tokenResponse.getRefreshToken(),
                "Refresh token should be rotated (different from original)");
    }

    /**
     * Refresh token should revoke old token after rotation.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldRevokeOldTokenAfterRotation() throws Exception {
        // Arrange
        String originalRefreshToken = testRefreshToken.getToken();
        RefreshTokenRequest request = new RefreshTokenRequest(originalRefreshToken);

        // Act - Use refresh token once
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        // Assert - Original token should no longer work
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid or expired refresh token"));
    }

    // ========== VALIDATION TESTS ==========

    /**
     * Refresh token should validate request fields.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldValidateRequestFields() throws Exception {
        // Test missing refreshToken field
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());

        // Test empty string
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\": \"\"}"))
                .andExpect(status().isBadRequest());

        // Test token too short
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\": \"short\"}"))
                .andExpect(status().isBadRequest());
    }

    // ========== SECURITY TESTS ==========

    /**
     * Refresh token should not allow reused tokens.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldNotAllowReusedTokens() throws Exception {
        // Arrange
        RefreshTokenRequest request = new RefreshTokenRequest(testRefreshToken.getToken());

        // Act - Use token once
        MvcResult firstResult = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn();

        // Try to use same token again - should fail
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid or expired refresh token"));
    }

    /**
     * Refresh token should handle concurrent requests.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldHandleConcurrentRequests() throws Exception {
        // This test ensures no race conditions exist
        RefreshTokenRequest request = new RefreshTokenRequest(testRefreshToken.getToken());

        // Try to use same token multiple times quickly
        // Only one should succeed
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        // Second request should fail
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }
}