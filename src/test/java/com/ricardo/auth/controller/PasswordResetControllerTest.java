package com.ricardo.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
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

    /**
     * Sets up.
     */
    @BeforeEach
    void setUp() {
        when(rateLimiter.isEnabled()).thenReturn(true);
        when(rateLimiter.allowRequest(anyString())).thenReturn(true);
        // Default: return null for IP unless overridden in test
        when(ipResolver.resolveIp(any(HttpServletRequest.class))).thenReturn(null);
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
     * Complete password reset with weak password should return bad request.
     *
     * @throws Exception the exception
     */
    @Test
    void completePasswordReset_WithWeakPassword_ShouldReturnBadRequest() throws Exception {
        // Given
        PasswordResetCompleteRequest request = new PasswordResetCompleteRequest();
        request.setPassword("123");
        request.setConfirmPassword("123");

        // When & Then
        mockMvc.perform(post("/api/auth/reset/valid-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());

        verify(passwordResetService, never()).completePasswordReset(anyString(), anyString());
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
     * Validate token with invalid token should return invalid.
     *
     * @throws Exception the exception
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void validateToken_WithInvalidToken_ShouldReturnInvalid() throws Exception {
        mockMvc.perform(get("/api/auth/reset/invalid-token/validate"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false));
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
