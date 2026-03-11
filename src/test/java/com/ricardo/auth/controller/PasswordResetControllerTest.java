package com.ricardo.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.core.PasswordResetService;
import com.ricardo.auth.core.RateLimiter;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.user.*;
import com.ricardo.auth.dto.PasswordResetCompleteRequest;
import com.ricardo.auth.dto.PasswordResetRequest;
import com.ricardo.auth.service.EventPublisher;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for PasswordResetController.
 * Tests security measures, rate limiting, and API endpoints.
 */
@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
class PasswordResetControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private PasswordResetService passwordResetService;

    @MockBean
    @Qualifier("passwordResetRateLimiter")
    private RateLimiter rateLimiter;

    @MockBean
    private EventPublisher eventPublisher;

    @MockBean
    private com.ricardo.auth.core.IpResolver ipResolver;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private UserService<User, AppRole, UUID> userService;

    @MockBean
    private PasswordPolicyService passwordPolicyService;

    /**
     * Sets up.
     */
    @BeforeEach
    void setUp() {
        when(rateLimiter.isEnabled()).thenReturn(true);
        when(rateLimiter.allowRequest(anyString())).thenReturn(true);
                // Default fallback IP for filter + controller paths
                when(ipResolver.resolveIp(any(HttpServletRequest.class))).thenReturn("127.0.0.1");
    }

    /**
     * Request password reset with valid email should return success.
     *
     * @throws Exception the exception
     */
    @Test
    void requestPasswordReset_WithValidEmail_ShouldReturnSuccess() throws Exception {
        // Given
        PasswordResetRequest request = new PasswordResetRequest();
        request.setEmail("user@example.com");

        // When & Then
        mockMvc.perform(post("/api/auth/reset-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value(
                        "If an account with that email exists, you will receive password reset instructions."));

        verify(passwordResetService).requestPasswordReset("user@example.com");
    }

    /**
     * Request password reset with invalid email should return bad request.
     *
     * @throws Exception the exception
     */
    @Test
    void requestPasswordReset_WithInvalidEmail_ShouldReturnBadRequest() throws Exception {
        // Given
        PasswordResetRequest request = new PasswordResetRequest();
        request.setEmail("invalid-email");

        // When & Then
        mockMvc.perform(post("/api/auth/reset-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());

        verify(passwordResetService, never()).requestPasswordReset(anyString());
    }

    /**
     * Request password reset with empty email should return bad request.
     *
     * @throws Exception the exception
     */
    @Test
    void requestPasswordReset_WithEmptyEmail_ShouldReturnBadRequest() throws Exception {
        // Given
        PasswordResetRequest request = new PasswordResetRequest();
        request.setEmail("");

        // When & Then
        mockMvc.perform(post("/api/auth/reset-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());

        verify(passwordResetService, never()).requestPasswordReset(anyString());
    }

    /**
     * Request password reset when rate limit exceeded should return too many requests.
     *
     * @throws Exception the exception
     */
    @Test
    void requestPasswordReset_WhenRateLimitExceeded_ShouldReturnTooManyRequests() throws Exception {
        // Given
        when(rateLimiter.allowRequest(anyString())).thenReturn(false);
        PasswordResetRequest request = new PasswordResetRequest();
        request.setEmail("user@example.com");

        // When & Then
        mockMvc.perform(post("/api/auth/reset-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().is(429))
                .andExpect(jsonPath("$.message").value("Too many requests. Please try again later."));

        verify(passwordResetService, never()).requestPasswordReset(anyString());
    }

    /**
     * Request password reset when service throws exception should still return success.
     *
     * @throws Exception the exception
     */
    @Test
    void requestPasswordReset_WhenServiceThrowsException_ShouldStillReturnSuccess() throws Exception {
        // Given
        PasswordResetRequest request = new PasswordResetRequest();
        request.setEmail("user@example.com");
        doThrow(new RuntimeException("Database error")).when(passwordResetService)
                .requestPasswordReset(anyString());

        // When & Then - Should still return success to prevent information leakage
        mockMvc.perform(post("/api/auth/reset-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value(
                        "If an account with that email exists, you will receive password reset instructions."));
    }

    /**
     * Complete password reset with valid request should return success.
     *
     * @throws Exception the exception
     */
    @Test
    void completePasswordReset_WithValidRequest_ShouldReturnSuccess() throws Exception {
        // Given
        PasswordResetCompleteRequest request = new PasswordResetCompleteRequest();
        request.setPassword("NewPassword123!");
        request.setConfirmPassword("NewPassword123!");

        // When & Then
        mockMvc.perform(post("/api/auth/reset/valid-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Password has been reset successfully."));

        verify(passwordResetService).completePasswordReset("valid-token", "NewPassword123!");
    }

        /**
         * Complete password reset should return bad request when service rejects password.
         *
         * @throws Exception the exception
         */
        @Test
        void completePasswordReset_WhenServiceRejectsPassword_ShouldReturnBadRequest() throws Exception {
                // Given
                PasswordResetCompleteRequest request = new PasswordResetCompleteRequest();
                request.setPassword("123");
                request.setConfirmPassword("123");

                doThrow(new IllegalArgumentException("Password does not meet complexity requirements"))
                                .when(passwordResetService)
                                .completePasswordReset("valid-token", "123");

                // When & Then
                mockMvc.perform(post("/api/auth/reset/valid-token")
                                                .contentType(MediaType.APPLICATION_JSON)
                                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isBadRequest());

                verify(passwordResetService).completePasswordReset("valid-token", "123");
        }

    /**
     * Complete password reset with mismatched passwords should return bad request.
     *
     * @throws Exception the exception
     */
    @Test
    void completePasswordReset_WithMismatchedPasswords_ShouldReturnBadRequest() throws Exception {
        // Given
        PasswordResetCompleteRequest request = new PasswordResetCompleteRequest();
        request.setPassword("NewPassword123!");
        request.setConfirmPassword("DifferentPassword123!");

        // When & Then
        mockMvc.perform(post("/api/auth/reset/valid-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Validation failed: passwordConfirmed Password and confirmation do not match; "));

        verify(passwordResetService, never()).completePasswordReset(anyString(), anyString());
    }

    /**
     * Complete password reset with security exception should return bad request.
     *
     * @throws Exception the exception
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void completePasswordReset_WithSecurityException_ShouldReturnBadRequest() throws Exception {
        // Given
        PasswordResetCompleteRequest request = new PasswordResetCompleteRequest();
        request.setPassword("NewPassword123!");
        request.setConfirmPassword("NewPassword123!");

        doThrow(new SecurityException("Invalid token")).when(passwordResetService)
                .completePasswordReset(anyString(), anyString());

        // When & Then
        mockMvc.perform(post("/api/auth/reset/invalid-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Invalid or expired token."));
    }

    /**
     * Complete password reset with illegal argument exception should return bad request.
     *
     * @throws Exception the exception
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void completePasswordReset_WithIllegalArgumentException_ShouldReturnBadRequest() throws Exception {
        // Given
        PasswordResetCompleteRequest request = new PasswordResetCompleteRequest();
        request.setPassword("NewPassword123!");
        request.setConfirmPassword("NewPassword123!");

        doThrow(new IllegalArgumentException("Password validation failed")).when(passwordResetService)
                .completePasswordReset(anyString(), anyString());

        // When & Then
        mockMvc.perform(post("/api/auth/reset/valid-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Password validation failed"));
    }

    /**
     * Complete password reset when rate limit exceeded should return too many requests.
     *
     * @throws Exception the exception
     */
    @Test
    void completePasswordReset_WhenRateLimitExceeded_ShouldReturnTooManyRequests() throws Exception {
        // Given
        when(rateLimiter.allowRequest(anyString())).thenReturn(false);
        PasswordResetCompleteRequest request = new PasswordResetCompleteRequest();
        request.setPassword("NewPassword123!");
        request.setConfirmPassword("NewPassword123!");

        // When & Then
        mockMvc.perform(post("/api/auth/reset/valid-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().is(429))
                .andExpect(jsonPath("$.error").value("Too many requests. Please try again later."));

        verify(passwordResetService, never()).completePasswordReset(anyString(), anyString());
    }

        /**
         * Request password reset should process when rate limiter is disabled.
         *
         * @throws Exception the exception
         */
        @Test
        void requestPasswordReset_WhenRateLimiterDisabled_ShouldStillProcessRequest() throws Exception {
                PasswordResetRequest request = new PasswordResetRequest();
                request.setEmail("user@example.com");

                when(rateLimiter.isEnabled()).thenReturn(false);

                mockMvc.perform(post("/api/auth/reset-request")
                                                .contentType(MediaType.APPLICATION_JSON)
                                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.message").value(
                                                "If an account with that email exists, you will receive password reset instructions."));

                verify(passwordResetService).requestPasswordReset("user@example.com");
                verify(rateLimiter, never()).allowRequest(anyString());
        }

        /**
         * Complete password reset should reject invalid token format.
         *
         * @throws Exception the exception
         */
        @Test
        void completePasswordReset_WithInvalidTokenFormat_ShouldReturnBadRequest() throws Exception {
                PasswordResetCompleteRequest request = new PasswordResetCompleteRequest();
                request.setPassword("NewPassword123!");
                request.setConfirmPassword("NewPassword123!");

                mockMvc.perform(post("/api/auth/reset/invalid token")
                                                .contentType(MediaType.APPLICATION_JSON)
                                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.error").value("Invalid token format."));

                verify(passwordResetService, never()).completePasswordReset(anyString(), anyString());
        }

        /**
         * Complete password reset should process when rate limiter is disabled.
         *
         * @throws Exception the exception
         */
        @Test
        void completePasswordReset_WhenRateLimiterDisabled_ShouldStillProcessRequest() throws Exception {
                PasswordResetCompleteRequest request = new PasswordResetCompleteRequest();
                request.setPassword("NewPassword123!");
                request.setConfirmPassword("NewPassword123!");

                when(rateLimiter.isEnabled()).thenReturn(false);

                mockMvc.perform(post("/api/auth/reset/valid-token")
                                                .contentType(MediaType.APPLICATION_JSON)
                                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.message").value("Password has been reset successfully."));

                verify(passwordResetService).completePasswordReset("valid-token", "NewPassword123!");
                verify(rateLimiter, never()).allowRequest(anyString());
        }

        /**
         * Complete password reset should return internal server error on unexpected exception.
         *
         * @throws Exception the exception
         */
        @Test
        void completePasswordReset_WhenUnexpectedExceptionOccurs_ShouldReturnInternalServerError() throws Exception {
                PasswordResetCompleteRequest request = new PasswordResetCompleteRequest();
                request.setPassword("NewPassword123!");
                request.setConfirmPassword("NewPassword123!");

                doThrow(new RuntimeException("Unexpected failure"))
                                .when(passwordResetService)
                                .completePasswordReset(anyString(), anyString());

                mockMvc.perform(post("/api/auth/reset/valid-token")
                                                .contentType(MediaType.APPLICATION_JSON)
                                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isInternalServerError())
                                .andExpect(jsonPath("$.error").value("An error occurred while resetting password."));
        }

    /**
     * Validate token with invalid token should return invalid.
     *
     * @throws Exception the exception
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void validateToken_WithInvalidToken_ShouldReturnInvalid() throws Exception {
        mockMvc.perform(get("/api/auth/reset/invalid-token/validate"))
                                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.valid").value(false));
    }

    /**
     * Validate token with valid token should return valid when service confirms token.
     *
     * @throws Exception the exception
     */
    @Test
    void validateToken_WithValidToken_ShouldReturnValid() throws Exception {
        when(passwordResetService.validatePasswordResetToken("valid-token")).thenReturn(true);

        mockMvc.perform(get("/api/auth/reset/valid-token/validate"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.message").value("Token is valid."));
    }

    /**
     * Validate token with malformed token should return invalid without calling service.
     *
     * @throws Exception the exception
     */
    @Test
    void validateToken_WithMalformedToken_ShouldReturnInvalidWithoutCallingService() throws Exception {
        mockMvc.perform(get("/api/auth/reset/invalid token/validate"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.message").value("Token is invalid or expired."));

        verify(passwordResetService, never()).validatePasswordResetToken(anyString());
    }

    /**
     * Validate token should return invalid when service throws security exception.
     *
     * @throws Exception the exception
     */
    @Test
    void validateToken_WhenServiceThrowsSecurityException_ShouldReturnInvalid() throws Exception {
        doThrow(new SecurityException("Token check failed"))
                .when(passwordResetService)
                .validatePasswordResetToken("valid-token");

        mockMvc.perform(get("/api/auth/reset/valid-token/validate"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.message").value("Token is invalid or expired."));
    }

    /**
     * Validate token should return invalid when service throws unexpected exception.
     *
     * @throws Exception the exception
     */
    @Test
    void validateToken_WhenServiceThrowsUnexpectedException_ShouldReturnInvalid() throws Exception {
        doThrow(new RuntimeException("Unexpected failure"))
                .when(passwordResetService)
                .validatePasswordResetToken("valid-token");

        mockMvc.perform(get("/api/auth/reset/valid-token/validate"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.message").value("Token is invalid or expired."));
    }

    /**
     * Validate token should return too many requests when rate limit is exceeded.
     *
     * @throws Exception the exception
     */
    @Test
    void validateToken_WhenRateLimitExceeded_ShouldReturnTooManyRequests() throws Exception {
        when(rateLimiter.allowRequest(anyString())).thenReturn(false);

        mockMvc.perform(get("/api/auth/reset/valid-token/validate"))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.message").value("Too many requests. Please try again later."));

                verify(rateLimiter).allowRequest("password_reset_validate:127.0.0.1");
        verify(passwordResetService, never()).validatePasswordResetToken(anyString());
    }

    /**
     * Request password reset with x forwarded for header should use correct ip.
     *
     * @throws Exception the exception
     */
    @Test
    void requestPasswordReset_WithXForwardedForHeader_ShouldUseCorrectIP() throws Exception {
        // Given
        PasswordResetRequest request = new PasswordResetRequest();
        request.setEmail("user@example.com");

        when(userService.getUserById(any(UUID.class))).thenReturn(new User(Username.valueOf("user123"), Email.valueOf("user@example.com"), Password.fromHash("Pass1234")));

        // Simulate resolver extracting the correct IP from header
        when(ipResolver.resolveIp(any(HttpServletRequest.class))).thenReturn("192.168.1.100");

        // When & Then
        mockMvc.perform(post("/api/auth/reset-request")
                        .header("X-Forwarded-For", "192.168.1.100, 10.0.0.1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        // Verify rate limiter was called with the correct IP
        verify(rateLimiter).allowRequest("password_reset:192.168.1.100");
    }

    /**
     * Request password reset with x real ip header should use correct ip.
     *
     * @throws Exception the exception
     */
    @Test
    void requestPasswordReset_WithXRealIPHeader_ShouldUseCorrectIP() throws Exception {
        // Given
        PasswordResetRequest request = new PasswordResetRequest();
        request.setEmail("user@example.com");
        // Simulate resolver extracting the correct IP from header
        when(ipResolver.resolveIp(any(HttpServletRequest.class))).thenReturn("192.168.1.200");

        // When & Then
        mockMvc.perform(post("/api/auth/reset-request")
                        .header("X-Real-IP", "192.168.1.200")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        // Verify rate limiter was called with the correct IP
        verify(rateLimiter).allowRequest("password_reset:192.168.1.200");
    }
}
