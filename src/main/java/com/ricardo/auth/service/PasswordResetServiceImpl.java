package com.ricardo.auth.service;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.*;
import com.ricardo.auth.domain.domainevents.PasswordResetCompletedEvent;
import com.ricardo.auth.domain.domainevents.PasswordResetRequestedEvent;
import com.ricardo.auth.domain.passwordresettoken.PasswordResetToken;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.helper.IdConverter;
import com.ricardo.auth.repository.PasswordResetToken.PasswordResetTokenRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

/**
 * OWASP-compliant password reset service implementation.
 * Implements timing attack prevention, rate limiting, and secure token generation.
 *
 * @since 3.1.0
 */
@Service
@Slf4j
public class PasswordResetServiceImpl<U extends AuthUser<ID, R>, R extends Role, ID> implements PasswordResetService {

    private final EmailSenderService emailSenderService;
    private final UserService<U, R, ID> userService;
    private final PasswordResetTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicyService;
    private final AuthProperties authProperties;
    private final Publisher eventPublisher;
    private final SecureRandom secureRandom = new SecureRandom();
    private final IdConverter<ID> idConverter;

    public PasswordResetServiceImpl(EmailSenderService emailSenderService,
                                    UserService<U, R, ID> userService,
                                    PasswordResetTokenRepository tokenRepository,
                                    PasswordEncoder passwordEncoder,
                                    PasswordPolicyService passwordPolicyService,
                                    AuthProperties authProperties,
                                    Publisher eventPublisher,
                                    IdConverter<ID> idConverter) {
        this.emailSenderService = emailSenderService;
        this.userService = userService;
        this.tokenRepository = tokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicyService = passwordPolicyService;
        this.authProperties = authProperties;
        this.eventPublisher = eventPublisher;
        this.idConverter = idConverter;
    }

    @Override
    @Transactional
    public void requestPasswordReset(String email) {
        if (email == null || email.isBlank()){
            log.warn("Password reset requested with null or empty email");
            return; // Don't reveal that email is invalid
        }
        long startTime = System.currentTimeMillis();

        try {
            // Validate email format
            if (!isValidEmail(email)) {
                log.warn("Invalid email format for password reset: {}", email);
                return; // Don't reveal that email is invalid
            }

            // Always process to prevent timing attacks
            U user = userService.getUserByEmail(email);

            if (user == null) {
                log.info("Password reset requested for non-existent email: {}", email);
                return; // Don't reveal that email is invalid
            }

            processPasswordResetRequest(user);


            // Always return success (prevent user enumeration)
            log.info("Password reset requested for email: {}", email);

        } finally {
            // Ensure consistent timing to prevent timing attacks
            ensureMinimumProcessingTime(startTime, 500); // 500ms minimum
        }
    }

    @Override
    @Transactional
    public void completePasswordReset(String token, String newPassword) {
        // Validate inputs
        if (token == null || token.trim().isEmpty()) {
            throw new IllegalArgumentException("Token is required");
        }

        if (!passwordPolicyService.validatePassword(newPassword)) {
            throw new IllegalArgumentException("Password does not meet security requirements");
        }

        // Find and validate token
        Optional<PasswordResetToken> tokenOpt = tokenRepository.findByTokenAndNotUsed(token);

        if (tokenOpt.isEmpty()) {
            log.warn("Invalid or expired password reset token used");
            throw new SecurityException("Invalid or expired token");
        }

        PasswordResetToken resetToken = tokenOpt.get();

        // Double-check expiration (defense in depth)
        if (resetToken.isExpired()) {
            log.warn("Expired password reset token used: {}", resetToken.getId());
            throw new SecurityException("Token has expired");
        }

        // Get user
        U user = userService.getUserById(idConverter.fromString(resetToken.getUserId().toString()));

        // Update password
        String encodedPassword = passwordEncoder.encode(newPassword);
        user.setPassword(encodedPassword);
        userService.updateUser(user.getId(), user);

        // Mark token as used
        resetToken.setUsed(true);
        resetToken.setUsedAt(Instant.now());
        tokenRepository.saveToken(resetToken);

        // Invalidate all other tokens for this user
        tokenRepository.invalidateTokensForUser(resetToken.getUserId(), Instant.now());

        log.info("Password reset completed for user: {}", user.getEmail());

        // Publish event
        eventPublisher.publishEvent(new PasswordResetCompletedEvent(
                user.getUsername(),
                user.getEmail()
        ));
    }


    @Override
    public boolean validatePasswordResetToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }

        Optional<PasswordResetToken> tokenOpt = tokenRepository.findByTokenAndNotUsed(token);
        return tokenOpt.isPresent() && !tokenOpt.get().isExpired();
    }

    private void processPasswordResetRequest(U user) {
        // Invalidate existing tokens
        tokenRepository.invalidateTokensForUser((UUID) user.getId(), Instant.now());

        // Generate new token
        String token = generateSecureToken();

        // Create and save token
        PasswordResetToken resetToken = new PasswordResetToken(
                token,
                (UUID) user.getId(),
                Instant.now().plusSeconds(authProperties.getPasswordReset().getTokenExpiryHours() * 3600L)
        );

        tokenRepository.saveToken(resetToken);

        // Send email
        sendPasswordResetEmail(user, token);

        // Publish event
        eventPublisher.publishEvent(new PasswordResetRequestedEvent(
                user.getUsername(),
                user.getEmail()
        ));
    }

    private String generateSecureToken() {
        byte[] tokenBytes = new byte[authProperties.getPasswordReset().getTokenLength()];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }

    private boolean isValidEmail(String email) {
        return email != null &&
                !email.trim().isEmpty() &&
                email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    }

    private void sendPasswordResetEmail(U user, String token) {
        String resetUrl = buildResetUrl(token);
        String subject = authProperties.getEmail().getResetSubject();
        String body = buildEmailBody(user.getUsername(), resetUrl);

        boolean sent = emailSenderService.sendEmail(user.getEmail(), subject, body);

        if (!sent) {
            log.error("Failed to send password reset email to: {}", user.getEmail());
            throw new RuntimeException("Failed to send password reset email");
        }
    }

    private String buildResetUrl(String token) {
        // Follow the standard pattern: /api/auth/reset/{token}
        return "/api/auth/reset/" + token;
    }

    private String buildEmailBody(String username, String resetUrl) {
        return String.format("""
                        Hello %s,
                        
                        We received a request to reset your password. If you made this request,
                        please click the link below to create a new password:
                        
                        %s
                        
                        This link will expire in %d hour(s). If you did not request a password reset,
                        please ignore this email and your password will remain unchanged.
                        
                        For security reasons, never share this link with anyone.
                        
                        Best regards,
                        %s
                        """,
                username,
                resetUrl,
                authProperties.getPasswordReset().getTokenExpiryHours(),
                authProperties.getEmail().getFromName()
        );
    }

    private void ensureMinimumProcessingTime(long startTime, long minimumMs) {
        long elapsed = System.currentTimeMillis() - startTime;
        if (elapsed < minimumMs) {
            try {
                Thread.sleep(minimumMs - elapsed);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}