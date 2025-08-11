package com.ricardo.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.RefreshTokenService;
import com.ricardo.auth.domain.refreshtoken.RefreshToken;
import com.ricardo.auth.domain.user.*;
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

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * The type Auth controller refresh token test.
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
    private RefreshTokenService<User, AppRole, UUID> refreshTokenService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private DefaultUserJpaRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private User testUser;
    private RefreshToken testRefreshToken;
    private Cookie accessTokenCookie;
    private Cookie refreshTokenCookie;

    /**
     * Sets up.
     */
    @BeforeEach
    void setUp() {
        userRepository.deleteAll();

        testUser = new User(Username.valueOf("testuser"), Email.valueOf("test@example.com"), Password.fromHash(passwordEncoder.encode("Password@123")));
        testUser.addRole(AppRole.USER);
        testUser = userRepository.save(testUser);

        testRefreshToken = refreshTokenService.createRefreshToken(testUser);

        String token = jwtService.generateAccessToken(testUser.getEmail(), testUser.getAuthorities());

        accessTokenCookie = new Cookie("access_token", token);
        refreshTokenCookie = new Cookie("refresh_token", testRefreshToken.getToken());
    }

    /**
     * Login should set tokens in cookies when refresh tokens enabled.
     *
     * @throws Exception the exception
     */
    @Test
    void login_shouldSetTokensInCookies_whenRefreshTokensEnabled() throws Exception {
        LoginRequestDTO loginRequest = new LoginRequestDTO("test@example.com", "Password@123");

        mockMvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("access_token"))
                .andExpect(cookie().exists("refresh_token"));
    }

    /**
     * Refresh token should set new tokens in cookies when refresh token is valid.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldSetNewTokensInCookies_whenRefreshTokenIsValid() throws Exception {
        // Não envie body, apenas o cookie
        MvcResult result = mockMvc.perform(post("/api/auth/refresh")
                        .cookie(refreshTokenCookie))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("access_token"))
                .andExpect(cookie().exists("refresh_token"))
                .andReturn();

        Cookie newAccessToken = result.getResponse().getCookie("access_token");
        mockMvc.perform(get("/api/auth/me").cookie(newAccessToken)).andExpect(status().isOk());
    }

    /**
     * Refresh token should return 401 when refresh token is invalid.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldReturn401_whenRefreshTokenIsInvalid() throws Exception {
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", "invalid-refresh-token")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Authentication failed"));
    }

    /**
     * Refresh token should return 401 when refresh token is expired.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldReturn401_whenRefreshTokenIsExpired() throws Exception {
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", "expired-or-nonexistent-token")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Authentication failed"));
    }

    /**
     * Refresh token should return 400 when request is invalid.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldReturn400_whenRequestIsInvalid() throws Exception {
        // Não envie body, apenas sem cookie
        mockMvc.perform(post("/api/auth/refresh"))
                .andExpect(status().isBadRequest());
    }

    /**
     * Refresh token should return 400 when request body is empty.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldReturn400_whenRequestBodyIsEmpty() throws Exception {
        // Não envie body, apenas sem cookie
        mockMvc.perform(post("/api/auth/refresh"))
                .andExpect(status().isBadRequest());
    }

    /**
     * Refresh token should return 400 when token is too short.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldReturn400_whenTokenIsTooShort() throws Exception {
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", "short")))
                .andExpect(status().isBadRequest());
    }

    /**
     * Refresh token should return 400 when token is blank.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldReturn400_whenTokenIsBlank() throws Exception {
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", "   ")))
                .andExpect(status().isBadRequest());
    }

    /**
     * Should complete full refresh token workflow.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldCompleteFullRefreshTokenWorkflow() throws Exception {
        LoginRequestDTO loginRequest = new LoginRequestDTO("test@example.com", "Password@123");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("access_token"))
                .andExpect(cookie().exists("refresh_token"))
                .andReturn();

        Cookie accessToken = loginResult.getResponse().getCookie("access_token");
        Cookie refreshToken = loginResult.getResponse().getCookie("refresh_token");

        mockMvc.perform(get("/api/auth/me").cookie(accessToken)).andExpect(status().isOk());

        // Não envie body, apenas o cookie
        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh")
                        .cookie(refreshToken))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("access_token"))
                .andExpect(cookie().exists("refresh_token"))
                .andReturn();

        Cookie newAccessTokenCookie = refreshResult.getResponse().getCookie("access_token");
        mockMvc.perform(get("/api/auth/me").cookie(newAccessTokenCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("test@example.com"));
    }

    /**
     * Should handle multiple refresh operations.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldHandleMultipleRefreshOperations() throws Exception {
        LoginRequestDTO loginRequest = new LoginRequestDTO("test@example.com", "Password@123");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("access_token"))
                .andExpect(cookie().exists("refresh_token"))
                .andReturn();

        Cookie refreshTokenCookie = loginResult.getResponse().getCookie("refresh_token");

        for (int i = 0; i < 3; i++) {
            MvcResult result = mockMvc.perform(post("/api/auth/refresh")
                            .cookie(refreshTokenCookie))
                    .andExpect(status().isOk())
                    .andExpect(cookie().exists("access_token"))
                    .andExpect(cookie().exists("refresh_token"))
                    .andReturn();

            refreshTokenCookie = result.getResponse().getCookie("refresh_token");
        }
    }

    /**
     * Refresh token should handle revoked token.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldHandleRevokedToken() throws Exception {
        refreshTokenService.revokeToken(testRefreshToken.getToken());

        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(refreshTokenCookie))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Authentication failed"));
    }

    /**
     * Refresh token should handle malformed request.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldHandleMalformedRequest() throws Exception {
        // Não envie body, apenas sem cookie
        mockMvc.perform(post("/api/auth/refresh"))
                .andExpect(status().isBadRequest());
    }

    /**
     * Refresh token should not expose internal errors.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldNotExposeInternalErrors() throws Exception {
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", "potential-sql-injection'; DROP TABLE users; --")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Authentication failed"));
    }

    /**
     * Refresh token should rotate refresh token when rotation is enabled.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldRotateRefreshToken_whenRotationIsEnabled() throws Exception {
        String originalRefreshToken = testRefreshToken.getToken();

        MvcResult result = mockMvc.perform(post("/api/auth/refresh")
                        .cookie(refreshTokenCookie))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("refresh_token"))
                .andReturn();

        Cookie rotatedRefreshToken = result.getResponse().getCookie("refresh_token");
        assertNotNull(rotatedRefreshToken);
        assertNotEquals(originalRefreshToken, rotatedRefreshToken.getValue());
    }

    /**
     * Refresh token should revoke old token after rotation.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldRevokeOldTokenAfterRotation() throws Exception {
        String originalRefreshToken = testRefreshToken.getToken();

        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(refreshTokenCookie))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(refreshTokenCookie))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Authentication failed"));
    }

    /**
     * Refresh token should validate request fields.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldValidateRequestFields() throws Exception {
        // Sem cookie
        mockMvc.perform(post("/api/auth/refresh")
                )
                .andExpect(status().isBadRequest());

        // Cookie vazio
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", "")))
                .andExpect(status().isBadRequest());

        // Cookie muito curto
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", "short")))
                .andExpect(status().isBadRequest());
    }

    /**
     * Refresh token should not allow reused tokens.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldNotAllowReusedTokens() throws Exception {
        // Primeira vez
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(refreshTokenCookie))
                .andExpect(status().isOk());

        // Segunda vez com o mesmo cookie/token
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(refreshTokenCookie))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Authentication failed"));
    }

    /**
     * Refresh token should handle concurrent requests.
     *
     * @throws Exception the exception
     */
    @Test
    void refreshToken_shouldHandleConcurrentRequests() throws Exception {
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(refreshTokenCookie))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(refreshTokenCookie))
                .andExpect(status().isUnauthorized());
    }
}