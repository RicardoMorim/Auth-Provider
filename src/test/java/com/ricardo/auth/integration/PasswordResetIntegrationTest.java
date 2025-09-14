package com.ricardo.auth.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.RateLimiter;
import com.ricardo.auth.domain.user.*;
import com.ricardo.auth.dto.PasswordResetCompleteRequest;
import com.ricardo.auth.dto.PasswordResetRequest;
import com.ricardo.auth.repository.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureWebMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for password reset functionality.
 * Tests the complete flow with real components.
 *
 * @since 3.1.0
 */
@SpringBootTest
@AutoConfigureWebMvc
@TestPropertySource(properties = {
        "ricardo.auth.password-reset.enabled=true",
        "ricardo.auth.password-reset.token-expiry-hours=1",
        "ricardo.auth.password-reset.max-attempts=5",
        "ricardo.auth.rate-limiter.enabled=true",
        "ricardo.auth.rate-limiter.max-requests=10",
        "ricardo.auth.rate-limiter.time-window-ms=60000",
        "ricardo.auth.jwt.secret=dGVzdC1zZWNyZXQtZm9yLWp3dC10b2tlbnMtaW4tdGVzdHMtb25seQ==",
})
@Transactional
class PasswordResetIntegrationTest {


    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AuthProperties authProperties;

    @Autowired
    @Qualifier("passwordResetRateLimiter")
    private RateLimiter rateLimiter;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private UserRepository<User, AppRole, UUID> userRepository;

    @BeforeEach
    public void setup() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
        rateLimiter.clearAll();
    }

    @Test
    void passwordResetFlow_WithValidConfiguration_ShouldWorkCorrectly() throws Exception {
        // Verify configuration is loaded correctly
        assert authProperties.getPasswordReset().isEnabled();
        assert authProperties.getPasswordReset().getTokenExpiryHours() == 1;

        assert rateLimiter.isEnabled();

        // Test password reset request
        PasswordResetRequest resetRequest = new PasswordResetRequest();
        resetRequest.setEmail("test@example.com");


        mockMvc.perform(post("/api/auth/reset-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(resetRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void rateLimiting_ShouldWorkWithExistingInfrastructure() throws Exception {
        // Test that rate limiting is properly integrated
        PasswordResetRequest resetRequest = new PasswordResetRequest();
        resetRequest.setEmail("test@example.com");

        User user = new User(Username.valueOf("user123"), Email.valueOf("test@example.com"), Password.fromHash("password"));
        userRepository.saveUser(user);

        // Make multiple requests to test rate limiting
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/auth/reset-request")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(resetRequest)))
                    .andExpect(status().isOk());
        }

        // The 6th request should be rate limited
        mockMvc.perform(post("/api/auth/reset-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(resetRequest)))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void passwordResetComplete_WithValidPassword_ShouldValidateCorrectly() throws Exception {
        PasswordResetCompleteRequest completeRequest = new PasswordResetCompleteRequest();
        completeRequest.setPassword("ValidPassword123!");
        completeRequest.setConfirmPassword("ValidPassword123!");

        // This will fail with invalid token, but validates the validation logic
        mockMvc.perform(post("/api/auth/reset/some-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(completeRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Invalid or expired token."));
    }

    @Test
    void passwordResetComplete_WithMismatchedPasswords_ShouldReturnError() throws Exception {
        PasswordResetCompleteRequest completeRequest = new PasswordResetCompleteRequest();
        completeRequest.setPassword("ValidPassword123!");
        completeRequest.setConfirmPassword("DifferentPassword123!");

        mockMvc.perform(post("/api/auth/reset/some-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(completeRequest))).andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Validation failed: passwordConfirmed Password and confirmation do not match; "));
    }
}
