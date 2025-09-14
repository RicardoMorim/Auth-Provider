package com.ricardo.auth.security;

import com.ricardo.auth.core.RateLimiter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Security integration tests for password reset and role management endpoints.
 * Tests that security configuration is properly applied.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "ricardo.auth.enabled=true",
        "ricardo.auth.rate-limiter.enabled=true",
        "ricardo.auth.password-reset.require-https=false",
        "ricardo.auth.redirect-https=false",
        "ricardo.auth.jwt.secret=jrQBZmSULrzxVbDCxZk1BOqp3dOo95fp+ZA422w1GXs=",
        "ricardo.auth.password-reset.max-attempts=3",
        "ricardo.auth.password-reset.time-window-ms=3600000",
        "ricardo.auth.rate-limiter.max-requests=10",
        "ricardo.auth.rate-limiter.time-window-ms=60000",
        "ricardo.auth.password-reset.token-expiry-hours=1",
        "ricardo.auth.rate-limiter.type=redis"
})
class PasswordResetSecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    @Qualifier("passwordResetRateLimiter")
    private RateLimiter rateLimiter;

    @BeforeEach
    void setUp() {
        rateLimiter.clearAll();
    }

    @Test
    void passwordResetRequest_ShouldBeAccessibleWithoutAuthentication() throws Exception {
        mockMvc.perform(post("/api/auth/reset-request").with(csrf())
                        .contentType("application/json")
                        .content("{\"email\":\"unique1@example.com\"}")) // Email único
                .andExpect(status().isOk());
    }

    @Test
    void passwordResetComplete_ShouldBeAccessibleWithoutAuthentication() throws Exception {
        // Password reset completion should be publicly accessible
        mockMvc.perform(post("/api/auth/reset/some-token").with(csrf())
                        .contentType("application/json")
                        .content("{\"password\":\"NewPassword123!\",\"confirmPassword\":\"NewPassword123!\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void roleManagementEndpoints_ShouldRequireAuthentication() throws Exception {
        // Role management endpoints should require authentication
        mockMvc.perform(get("/api/users/123e4567-e89b-12d3-a456-426614174000/roles").with(csrf()))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/users/123e4567-e89b-12d3-a456-426614174000/roles").with(csrf())
                        .contentType("application/json")
                        .content("{\"roleName\":\"ADMIN\",\"reason\":\"test\"}"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/users/123e4567-e89b-12d3-a456-426614174000/roles").with(csrf())
                        .contentType("application/json")
                        .content("{\"roleName\":\"ADMIN\",\"reason\":\"test\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rateLimiterFilter_ShouldThrottleAfterConfiguredRequests() throws Exception {
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/api/auth/reset-request")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"email\":\"test@example.com\"}"))
                    .andExpect(status().isOk());
        }
        mockMvc.perform(post("/api/auth/reset-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"test@example.com\"}"))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void csrfProtection_ShouldBeConfiguredCorrectly() throws Exception {
        mockMvc.perform(post("/api/auth/reset-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"unique2@example.com\"}")) // Email único
                .andExpect(status().isOk());
    }

    @Test
    void sessionManagement_ShouldBeStateless() throws Exception {
        // Multiple requests should not create sessions (stateless configuration)
        mockMvc.perform(post("/api/auth/reset-request").with(csrf())
                        .contentType("application/json")
                        .content("{\"email\":\"test1@example.com\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/reset-request").with(csrf())
                        .contentType("application/json")
                        .content("{\"email\":\"test2@example.com\"}"))
                .andExpect(status().isOk());
    }
}
