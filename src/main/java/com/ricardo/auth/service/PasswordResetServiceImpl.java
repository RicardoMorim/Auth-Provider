package com.ricardo.auth.service;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.*;
import com.ricardo.auth.domain.domainevents.PasswordResetCompletedEvent;
import com.ricardo.auth.domain.domainevents.PasswordResetRequestedEvent;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import com.ricardo.auth.domain.passwordresettoken.PasswordResetToken;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.helper.IdConverter;
import com.ricardo.auth.repository.PasswordResetToken.PasswordResetTokenRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;


/**
 * The type Password reset service.
 *
 * @param <U>  the type parameter
 * @param <R>  the type parameter
 * @param <ID> the type parameter
 */
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
    private final AuthProperties properties;
    private final CacheManager cacheManager;

    /**
     * The constant PASSWORD_RESET_KEY_PREFIX.
     */
    public static final String PASSWORD_RESET_KEY_PREFIX = "password_reset:";
    /**
     * The constant PASSWORD_RESET_COMPLETE_KEY_PREFIX.
     */
    public static final String PASSWORD_RESET_COMPLETE_KEY_PREFIX = "password_reset_complete:";


    /**
     * Instantiates a new Password reset service.
     *
     * @param emailSenderService    the email sender service
     * @param userService           the user service
     * @param tokenRepository       the token repository
     * @param passwordEncoder       the password encoder
     * @param passwordPolicyService the password policy service
     * @param authProperties        the auth properties
     * @param eventPublisher        the event publisher
     * @param idConverter           the id converter
     * @param properties            the properties
     */
    public PasswordResetServiceImpl(EmailSenderService emailSenderService,
                                    UserService<U, R, ID> userService,
                                    PasswordResetTokenRepository tokenRepository,
                                    PasswordEncoder passwordEncoder,
                                    PasswordPolicyService passwordPolicyService,
                                    AuthProperties authProperties,
                                    Publisher eventPublisher,
                                    IdConverter<ID> idConverter,
                                    AuthProperties properties,
                                    CacheManager cacheManager) {
        this.emailSenderService = emailSenderService;
        this.userService = userService;
        this.tokenRepository = tokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicyService = passwordPolicyService;
        this.authProperties = authProperties;
        this.eventPublisher = eventPublisher;
        this.idConverter = idConverter;
        this.properties = properties;
        this.cacheManager = cacheManager;
    }

    @Override
    @Transactional
    public void requestPasswordReset(String email) {
        if (email == null || email.isBlank()) {
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

        } catch (ResourceNotFoundException e) {
            log.info("Password reset requested for non-existent email: {}", email);
            return; // Don't reveal that email is invalid
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
        String hashedToken = hashToken(token);
        Optional<PasswordResetToken> tokenOpt = tokenRepository.findByTokenAndNotUsed(hashedToken);

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
        U user = userService.getUserByEmail(resetToken.getEmail());
        if (user == null) {
            log.warn("Password reset token used for non-existent user: {}", resetToken.getEmail());
            throw new SecurityException("Invalid token");
        }


        // Update password
        String encodedPassword = passwordEncoder.encode(newPassword);
        user.setPassword(encodedPassword);
        userService.updatePassword(user.getId(), encodedPassword);

        // Mark token as used
        resetToken.setUsed(true);
        resetToken.setUsedAt(Instant.now());
        tokenRepository.saveToken(resetToken);

        // Invalidate all other tokens for this user
        tokenRepository.invalidateTokensForUser(user.getEmail(), Instant.now());

        log.info("Password reset completed for user: {}", user.getEmail());

        // Publish event
        eventPublisher.publishEvent(new PasswordResetCompletedEvent(
                user.getUsername(),
                user.getEmail()
        ));

        evictCache("userById", user.getId());
        evictCache("userByEmail", user.getEmail());
        evictCache("userByUsername", user.getUsername());
        evictCache("userExists", user.getEmail());
        clearCache("users");
        clearCache("adminCount");
    }


    @Override
    public boolean validatePasswordResetToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }

        String hashedToken = hashToken(token);
        Optional<PasswordResetToken> tokenOpt = tokenRepository.findByTokenAndNotUsed(hashedToken);
        return tokenOpt.isPresent() && !tokenOpt.get().isExpired();
    }

    private void processPasswordResetRequest(U user) {
        // Invalidate existing tokens
        tokenRepository.invalidateTokensForUser(user.getEmail(), Instant.now());

        // Generate new raw token (only ever emailed to the user)
        String token = generateSecureToken();
        String hashedToken = hashToken(token);

        // Create and save token
        PasswordResetToken resetToken = new PasswordResetToken(
                hashedToken,
                user.getEmail(),
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
        return properties.getBaseUrl() + "api/auth/reset/" + token;
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

    /**
     * Hash the raw reset token using SHA-256 and encode as Base64 URL-safe (no padding).
     * This ensures tokens are never stored in plaintext at rest.
     *
     * @param rawToken the raw token
     * @return the string
     */
    public static String hashToken(String rawToken) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }

    private void evictCache(String cacheName, Object key) {
        Cache cache = cacheManager.getCache(cacheName);
        if (cache != null) {
            cache.evict(key);
        }
    }

    private void clearCache(String cacheName) {
        Cache cache = cacheManager.getCache(cacheName);
        if (cache != null) {
            cache.clear();
        }
    }
}