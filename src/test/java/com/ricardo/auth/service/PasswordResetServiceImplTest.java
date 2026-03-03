package com.ricardo.auth.service;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.EmailSenderService;
import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.core.Publisher;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.domainevents.PasswordResetCompletedEvent;
import com.ricardo.auth.domain.domainevents.PasswordResetRequestedEvent;
import com.ricardo.auth.domain.passwordresettoken.PasswordResetToken;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.helper.IdConverter;
import com.ricardo.auth.repository.PasswordResetToken.PasswordResetTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cache.CacheManager;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive tests for PasswordResetServiceImpl.
 * Tests OWASP security measures and business logic.
 *
 */
@ExtendWith(MockitoExtension.class)
class PasswordResetServiceImplTest {

    /**
     * The Id converter.
     */
    @Mock
    IdConverter<UUID> idConverter;
    /**
     * The Cache manager.
     */
    @Mock
    CacheManager cacheManager;
    @Mock
    private EmailSenderService emailSenderService;
    @Mock
    private UserService<TestUser, TestRole, UUID> userService;
    @Mock
    private PasswordResetTokenRepository tokenRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private PasswordPolicyService passwordPolicyService;
    @Mock
    private Publisher eventPublisher;
    private AuthProperties authProperties;
    private PasswordResetServiceImpl<TestUser, TestRole, UUID> passwordResetService;

    /**
     * Sets up.
     */
    @BeforeEach
    void setUp() {
        authProperties = createAuthProperties();
        passwordResetService = new PasswordResetServiceImpl<>(
                emailSenderService,
                userService,
                tokenRepository,
                passwordEncoder,
                passwordPolicyService,
                authProperties,
                eventPublisher,
                idConverter, cacheManager
        );
    }

    /**
     * Request password reset with valid email should process successfully.
     */
    @Test
    void requestPasswordReset_WithValidEmail_ShouldProcessSuccessfully() {
        // Given
        String email = "user@example.com";
        TestUser user = createTestUser(email);
        when(userService.getUserByEmail(email)).thenReturn(user);
        when(emailSenderService.sendEmail(anyString(), anyString(), anyString())).thenReturn(true);

        // When
        passwordResetService.requestPasswordReset(email);

        // Then
        verify(tokenRepository).invalidateTokensForUser(eq(email), any(Instant.class));
        verify(tokenRepository).saveToken(any(PasswordResetToken.class));
        verify(emailSenderService).sendEmail(eq(email), anyString(), anyString());

        ArgumentCaptor<PasswordResetRequestedEvent> eventCaptor =
                ArgumentCaptor.forClass(PasswordResetRequestedEvent.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());

        PasswordResetRequestedEvent event = eventCaptor.getValue();
        assertThat(event.username()).isEqualTo(user.getUsername());
        assertThat(event.email()).isEqualTo(email);
    }

    /**
     * Request password reset with requireHttps enabled should send HTTPS reset URL.
     */
    @Test
    void requestPasswordReset_WithRequireHttpsEnabled_ShouldSendHttpsResetUrl() {
        String email = "user@example.com";
        TestUser user = createTestUser(email);
        authProperties.setBaseUrl("http://localhost:8080");
        authProperties.getPasswordReset().setRequireHttps(true);

        when(userService.getUserByEmail(email)).thenReturn(user);
        when(emailSenderService.sendEmail(anyString(), anyString(), anyString())).thenReturn(true);

        passwordResetService.requestPasswordReset(email);

        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailSenderService).sendEmail(eq(email), anyString(), bodyCaptor.capture());
        assertThat(bodyCaptor.getValue()).contains("https://localhost:8080/api/auth/reset/");
    }

    /**
     * Request password reset with invalid base URL scheme should fail when requireHttps is enabled.
     */
    @Test
    void requestPasswordReset_WithInvalidBaseUrlScheme_ShouldThrowWhenRequireHttpsEnabled() {
        String email = "user@example.com";
        TestUser user = createTestUser(email);
        authProperties.setBaseUrl("localhost:8080");
        authProperties.getPasswordReset().setRequireHttps(true);

        when(userService.getUserByEmail(email)).thenReturn(user);

        assertThatThrownBy(() -> passwordResetService.requestPasswordReset(email))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("must use HTTPS");
    }

    /**
     * Request password reset with nonexistent email should not throw exception.
     */
    @Test
    void requestPasswordReset_WithNonexistentEmail_ShouldNotThrowException() {
        // Given
        String email = "nonexistent@example.com";
        when(userService.getUserByEmail(email)).thenReturn(null);

        // When & Then - Should not throw exception (prevent user enumeration)
        passwordResetService.requestPasswordReset(email);

        // Verify no tokens are created for non-existent users
        verify(tokenRepository, never()).saveToken(any());
        verify(emailSenderService, never()).sendEmail(anyString(), anyString(), anyString());
    }

    /**
     * Request password reset with invalid email should not throw exception.
     */
    @Test
    void requestPasswordReset_WithInvalidEmail_ShouldNotThrowException() {
        // Given
        String invalidEmail = "invalid-email";

        // When & Then - Should not throw exception (prevent information leakage)
        passwordResetService.requestPasswordReset(invalidEmail);

        verify(userService, never()).getUserByEmail(anyString());
        verify(tokenRepository, never()).saveToken(any());
    }

    /**
     * Request password reset with null email should not throw exception.
     */
    @Test
    void requestPasswordReset_WithNullEmail_ShouldNotThrowException() {
        // When & Then - Should handle gracefully (OWASP requirement)
        passwordResetService.requestPasswordReset(null);

        verify(userService, never()).getUserByEmail(anyString());
        verify(tokenRepository, never()).saveToken(any());
    }

    /**
     * Complete password reset with valid token should update password.
     */
    @Test
    void completePasswordReset_WithValidToken_ShouldUpdatePassword() {
        // Given
        String token = "valid-token";
        String newPassword = "NewPassword123!";
        TestUser user = createTestUser("user@example.com");
        UUID userId = user.getId(); // Use the user's actual ID

        userService.createUser(user);

        PasswordResetToken resetToken = new PasswordResetToken(
                token, user.getEmail(), Instant.now().plusSeconds(3600)
        );

        when(passwordPolicyService.validatePassword(newPassword)).thenReturn(true);
        when(tokenRepository.findByTokenAndNotUsed(PasswordResetServiceImpl.hashToken(token))).thenReturn(Optional.of(resetToken));
        when(passwordEncoder.encode(newPassword)).thenReturn("encoded-password");
        when(userService.getUserByEmail(user.getEmail())).thenReturn(user);

        // When
        passwordResetService.completePasswordReset(token, newPassword);

        // Then
        verify(passwordEncoder).encode(newPassword);
        verify(userService).updatePassword(eq(userId), any(String.class));
        verify(tokenRepository).saveToken(argThat(PasswordResetToken::isUsed));
        verify(tokenRepository).invalidateTokensForUser(eq(user.getEmail()), any(Instant.class));

        ArgumentCaptor<PasswordResetCompletedEvent> eventCaptor =
                ArgumentCaptor.forClass(PasswordResetCompletedEvent.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());

        PasswordResetCompletedEvent event = eventCaptor.getValue();
        assertThat(event.username()).isEqualTo(user.getUsername());
        assertThat(event.email()).isEqualTo(user.getEmail());
    }

    /**
     * Complete password reset with null token should throw exception.
     */
    @Test
    void completePasswordReset_WithNullToken_ShouldThrowException() {
        // Given
        String newPassword = "NewPassword123!";

        // When & Then
        assertThatThrownBy(() -> passwordResetService.completePasswordReset(null, newPassword))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Token is required");
    }

    /**
     * Complete password reset with empty token should throw exception.
     */
    @Test
    void completePasswordReset_WithEmptyToken_ShouldThrowException() {
        // Given
        String newPassword = "NewPassword123!";

        // When & Then
        assertThatThrownBy(() -> passwordResetService.completePasswordReset("", newPassword))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Token is required");
    }

    /**
     * Complete password reset with invalid password should throw exception.
     */
    @Test
    void completePasswordReset_WithInvalidPassword_ShouldThrowException() {
        // Given
        String token = "valid-token";
        String weakPassword = "123";
        when(passwordPolicyService.validatePassword(weakPassword)).thenReturn(false);

        // When & Then
        assertThatThrownBy(() -> passwordResetService.completePasswordReset(token, weakPassword))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Password does not meet security requirements");
    }

    /**
     * Complete password reset with expired token should throw exception.
     */
    @Test
    void completePasswordReset_WithExpiredToken_ShouldThrowException() {
        // Given
        String token = "expired-token";
        String newPassword = "NewPassword123!";

        PasswordResetToken expiredToken = new PasswordResetToken(
                token, "randomemail@email.com", Instant.now().minusSeconds(3600)
        );

        when(passwordPolicyService.validatePassword(newPassword)).thenReturn(true);
        when(tokenRepository.findByTokenAndNotUsed(PasswordResetServiceImpl.hashToken(token))).thenReturn(Optional.of(expiredToken));

        // When & Then
        assertThatThrownBy(() -> passwordResetService.completePasswordReset(token, newPassword))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Token has expired");
    }

    /**
     * Complete password reset with nonexistent token should throw exception.
     */
    @Test
    void completePasswordReset_WithNonexistentToken_ShouldThrowException() {
        // Given
        String token = "nonexistent-token";
        String newPassword = "NewPassword123!";

        when(passwordPolicyService.validatePassword(newPassword)).thenReturn(true);
        when(tokenRepository.findByTokenAndNotUsed(PasswordResetServiceImpl.hashToken(token))).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> passwordResetService.completePasswordReset(token, newPassword))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Invalid or expired token");
    }

            /**
             * Complete password reset with token for missing user should throw exception.
             */
            @Test
            void completePasswordReset_WithMissingUser_ShouldThrowSecurityException() {
            String token = "valid-token";
            String newPassword = "NewPassword123!";

            PasswordResetToken resetToken = new PasswordResetToken(
                PasswordResetServiceImpl.hashToken(token), "missing@example.com", Instant.now().plusSeconds(3600)
            );

            when(passwordPolicyService.validatePassword(newPassword)).thenReturn(true);
            when(tokenRepository.findByTokenAndNotUsed(PasswordResetServiceImpl.hashToken(token))).thenReturn(Optional.of(resetToken));
            when(userService.getUserByEmail("missing@example.com")).thenReturn(null);

            assertThatThrownBy(() -> passwordResetService.completePasswordReset(token, newPassword))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Invalid token");
            }

            /**
             * Request password reset should throw when email delivery fails.
             */
            @Test
            void requestPasswordReset_WhenEmailSendFails_ShouldThrowRuntimeException() {
            String email = "user@example.com";
            TestUser user = createTestUser(email);

            when(userService.getUserByEmail(email)).thenReturn(user);
            when(emailSenderService.sendEmail(anyString(), anyString(), anyString())).thenReturn(false);

            assertThatThrownBy(() -> passwordResetService.requestPasswordReset(email))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to send password reset email");
            }

            /**
             * Validate token should return false for null token.
             */
            @Test
            void validatePasswordResetToken_WithNullToken_ShouldReturnFalse() {
            assertThat(passwordResetService.validatePasswordResetToken(null)).isFalse();
            verify(tokenRepository, never()).findByTokenAndNotUsed(anyString());
            }

            /**
             * Validate token should return false for expired token.
             */
            @Test
            void validatePasswordResetToken_WithExpiredToken_ShouldReturnFalse() {
            String token = "expired-token";
            PasswordResetToken expiredToken = new PasswordResetToken(
                PasswordResetServiceImpl.hashToken(token),
                "user@example.com",
                Instant.now().minusSeconds(60)
            );

            when(tokenRepository.findByTokenAndNotUsed(PasswordResetServiceImpl.hashToken(token)))
                .thenReturn(Optional.of(expiredToken));

            assertThat(passwordResetService.validatePasswordResetToken(token)).isFalse();
            }

            /**
             * Validate token should return true for valid and non-expired token.
             */
            @Test
            void validatePasswordResetToken_WithValidToken_ShouldReturnTrue() {
            String token = "valid-token";
            PasswordResetToken validToken = new PasswordResetToken(
                PasswordResetServiceImpl.hashToken(token),
                "user@example.com",
                Instant.now().plusSeconds(3600)
            );

            when(tokenRepository.findByTokenAndNotUsed(PasswordResetServiceImpl.hashToken(token)))
                .thenReturn(Optional.of(validToken));

            assertThat(passwordResetService.validatePasswordResetToken(token)).isTrue();
            }


    /**
     * Request password reset should ensure minimum processing time.
     */
    @Test
    void requestPasswordReset_ShouldEnsureMinimumProcessingTime() {
        // Given
        String email = "user@example.com";
        long startTime = System.currentTimeMillis();

        // When
        passwordResetService.requestPasswordReset(email);
        long endTime = System.currentTimeMillis();

        // Then - Should take at least 500ms (timing attack prevention)
        assertThat(endTime - startTime).isGreaterThanOrEqualTo(500);
    }

    private AuthProperties createAuthProperties() {
        AuthProperties properties = new AuthProperties();

        AuthProperties.PasswordReset passwordReset = new AuthProperties.PasswordReset();
        passwordReset.setTokenLength(32);
        passwordReset.setTokenExpiryHours(1);
        passwordReset.setMaxAttempts(3);
        properties.setPasswordReset(passwordReset);

        AuthProperties.Email email = new AuthProperties.Email();
        email.setFromAddress("noreply@test.com");
        email.setFromName("Test App");
        email.setResetSubject("Password Reset Request");
        properties.setEmail(email);

        return properties;
    }

    private TestUser createTestUser(String email) {
        TestUser user = new TestUser();
        user.setId(UUID.randomUUID());
        user.setUsername("testuser");
        user.setEmail(email);
        user.setPassword("current-password");
        return user;
    }

    // Test helper classes
    private static class TestUser implements AuthUser<UUID, TestRole> {
        private UUID id;
        private String username;
        private String email;
        private String password;
        private Long Version;
        private Set<TestRole> roles;
        private Instant createdAt;
        private Instant updatedAt;

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return roles.stream()
                    .map(role -> new SimpleGrantedAuthority(role.getAuthority()))
                    .collect(Collectors.toSet());
        }

        @Override
        public Instant getUpdatedAt() {
            return updatedAt;
        }

        @Override
        public void setUpdatedAt(Instant updatedAt) {
            this.updatedAt = updatedAt;
        }

        @Override
        public Instant getCreatedAt() {
            return createdAt;
        }

        @Override
        public void setCreatedAt(Instant createdAt) {
            this.createdAt = createdAt;
        }

        @Override
        public Long getVersion() {
            return Version;
        }

        @Override
        public void setVersion(Long version) {
            this.Version = version;
        }

        @Override
        public UUID getId() {
            return id;
        }

        public void setId(UUID id) {
            this.id = id;
        }

        @Override
        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        @Override
        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        @Override
        public String getPassword() {
            return password;
        }

        @Override
        public void setPassword(String password) {
            this.password = password;
        }

        @Override
        public java.util.Set<TestRole> getRoles() {
            return java.util.Set.of();
        }

        @Override
        public void setRoles(Set<TestRole> roles) {
            this.roles = roles;
        }

        @Override
        public void addRole(TestRole role) {
        }

        @Override
        public void removeRole(TestRole role) {
        }
    }

    private static class TestRole implements com.ricardo.auth.core.Role {
        @Override
        public String getAuthority() {
            return "USER";
        }
    }
}
