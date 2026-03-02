package com.ricardo.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ricardo.auth.core.IpResolver;
import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.core.PasswordResetService;
import com.ricardo.auth.core.RateLimiter;
import com.ricardo.auth.dto.PasswordResetCompleteRequest;
import com.ricardo.auth.repository.PasswordResetToken.PasswordResetTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
class PasswordResetControllerRealServiceTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @SpyBean
    private PasswordResetService passwordResetService;

    @MockBean
    private PasswordPolicyService passwordPolicyService;

    @MockBean
    private PasswordResetTokenRepository tokenRepository;

    @MockBean
    @Qualifier("passwordResetRateLimiter")
    private RateLimiter rateLimiter;

    @MockBean
    private IpResolver ipResolver;

    @BeforeEach
    void setUp() {
        when(rateLimiter.isEnabled()).thenReturn(true);
        when(rateLimiter.allowRequest(any())).thenReturn(true);
        when(ipResolver.resolveIp(any(HttpServletRequest.class))).thenReturn("127.0.0.1");
    }

    @Test
    void completePasswordReset_WithWeakPassword_ShouldReturnBadRequest() throws Exception {
        PasswordResetCompleteRequest request = new PasswordResetCompleteRequest();
        request.setPassword("123");
        request.setConfirmPassword("123");

        when(passwordPolicyService.validatePassword("123")).thenReturn(false);

        mockMvc.perform(post("/api/auth/reset/valid-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Password does not meet security requirements"));

        verify(passwordResetService).completePasswordReset("valid-token", "123");
        verify(tokenRepository, never()).findByTokenAndNotUsed(any());
    }
}
