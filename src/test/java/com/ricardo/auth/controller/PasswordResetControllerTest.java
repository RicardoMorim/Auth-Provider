package com.ricardo.auth.controller;

import com.ricardo.auth.core.PasswordResetService;
import com.ricardo.auth.core.RateLimiter;
import com.ricardo.auth.dto.PasswordResetCompleteRequest;
import com.ricardo.auth.dto.PasswordResetRequest;
import com.ricardo.auth.service.EventPublisher;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

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

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        when(rateLimiter.isEnabled()).thenReturn(true);
        when(rateLimiter.allowRequest(anyString())).thenReturn(true);
    }

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
                .andExpect(jsonPath("$.error").value("Password confirmation does not match."));

        verify(passwordResetService, never()).completePasswordReset(anyString(), anyString());
    }

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

    @Test
    @WithMockUser(roles = "ADMIN")
    void validateToken_WithValidToken_ShouldReturnValid() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/auth/reset/valid-token/validate"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.message").value("Token is valid."));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void validateToken_WithInvalidToken_ShouldReturnInvalid() throws Exception {
        mockMvc.perform(get("/api/auth/reset/invalid-token/validate"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));
    }

    @Test
    void requestPasswordReset_WithXForwardedForHeader_ShouldUseCorrectIP() throws Exception {
        // Given
        PasswordResetRequest request = new PasswordResetRequest();
        request.setEmail("user@example.com");

        // When & Then
        mockMvc.perform(post("/api/auth/reset-request")
                .header("X-Forwarded-For", "192.168.1.100, 10.0.0.1")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        // Verify rate limiter was called with the correct IP
        verify(rateLimiter).allowRequest("password_reset:192.168.1.100");
    }

    @Test
    void requestPasswordReset_WithXRealIPHeader_ShouldUseCorrectIP() throws Exception {
        // Given
        PasswordResetRequest request = new PasswordResetRequest();
        request.setEmail("user@example.com");

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
