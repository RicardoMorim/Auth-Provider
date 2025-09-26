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

    // --- LOG SANITIZATION HELPER ---
    private static String sanitizeForLogging(String input) {
        if (input == null) {
            return "null";
        }
        return input
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
                .replace("\"", "\\\"")
                .trim();
    }

    private static String sanitizeIdForLogging(Object id) {
        if (id == null) return "null";
        return sanitizeForLogging(id.toString());
    }

    @Override
    @Transactional
    public void requestPasswordReset(String email) {
        if (email == null || email.isBlank()) {
            log.warn("Password reset requested with null or empty email");
            return;
        }
        long startTime = System.currentTimeMillis();

        try {
            if (!isValidEmail(email)) {
                log.warn("Invalid email format for password reset: {}", sanitizeForLogging(email));
                return;
            }

            U user = userService.getUserByEmail(email);

            if (user == null) {
                log.info("Password reset requested for non-existent email: {}", sanitizeForLogging(email));
                return;
            }

            processPasswordResetRequest(user);

            log.info("Password reset requested for email: {}", sanitizeForLogging(email));

        } catch (ResourceNotFoundException e) {
            log.info("Password reset requested for non-existent email: {}", sanitizeForLogging(email));
            return;
        } finally {
            ensureMinimumProcessingTime(startTime, 500);
        }
    }

    @Override
    @Transactional
    public void completePasswordReset(String token, String newPassword) {
        if (token == null || token.trim().isEmpty()) {
            throw new IllegalArgumentException("Token is required");
        }

        if (!passwordPolicyService.validatePassword(newPassword)) {
            throw new IllegalArgumentException("Password does not meet security requirements");
        }

        String hashedToken = hashToken(token);
        long findTokenStartTime = System.currentTimeMillis();
        log.debug("Attempting to find password reset token");
        Optional<PasswordResetToken> tokenOpt = tokenRepository.findByTokenAndNotUsed(hashedToken);
        log.info("Password reset token lookup completed in {}ms", System.currentTimeMillis() - findTokenStartTime);

        if (tokenOpt.isEmpty()) {
            log.warn("Invalid or expired password reset token used");
            throw new SecurityException("Invalid or expired token");
        }

        PasswordResetToken resetToken = tokenOpt.get();

        if (resetToken.isExpired()) {
            log.warn("Expired password reset token used: {}", sanitizeIdForLogging(resetToken.getId()));
            throw new SecurityException("Token has expired");
        }

        U user = userService.getUserByEmail(resetToken.getEmail());
        if (user == null) {
            log.warn("Password reset token used for non-existent user: {}", sanitizeForLogging(resetToken.getEmail()));
            throw new SecurityException("Invalid token");
        }

        String encodedPassword = passwordEncoder.encode(newPassword);
        user.setPassword(encodedPassword);
        userService.updatePassword(user.getId(), encodedPassword);

        resetToken.setUsed(true);
        resetToken.setUsedAt(Instant.now());
        long saveTokenStartTime = System.currentTimeMillis();
        log.debug("Attempting to mark password reset token as used for user: {}", sanitizeForLogging(user.getEmail()));
        tokenRepository.saveToken(resetToken);
        log.info("Password reset token for user {} marked as used in {}ms", sanitizeForLogging(user.getEmail()), System.currentTimeMillis() - saveTokenStartTime);

        long invalidateStartTime = System.currentTimeMillis();
        log.debug("Attempting to invalidate other password reset tokens for user: {}", sanitizeForLogging(user.getEmail()));
        tokenRepository.invalidateTokensForUser(user.getEmail(), Instant.now());
        log.info("Other password reset tokens for user {} invalidated in {}ms", sanitizeForLogging(user.getEmail()), System.currentTimeMillis() - invalidateStartTime);

        log.info("Password reset completed for user: {}", sanitizeForLogging(user.getEmail()));

        eventPublisher.publishEvent(new PasswordResetCompletedEvent(
                sanitizeForLogging(user.getUsername()),
                sanitizeForLogging(user.getEmail())
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
        long startTime = System.currentTimeMillis();
        log.debug("Attempting to validate password reset token");
        Optional<PasswordResetToken> tokenOpt = tokenRepository.findByTokenAndNotUsed(hashedToken);
        boolean isValid = tokenOpt.isPresent() && !tokenOpt.get().isExpired();
        log.info("Password reset token validation completed in {}ms. Is valid: {}", System.currentTimeMillis() - startTime, isValid);
        return isValid;
    }

    private void processPasswordResetRequest(U user) {
        long invalidateStartTime = System.currentTimeMillis();
        log.debug("Attempting to invalidate existing password reset tokens for user: {}", sanitizeForLogging(user.getEmail()));
        tokenRepository.invalidateTokensForUser(user.getEmail(), Instant.now());
        log.info("Existing password reset tokens for user {} invalidated in {}ms", sanitizeForLogging(user.getEmail()), System.currentTimeMillis() - invalidateStartTime);

        String token = generateSecureToken();
        String hashedToken = hashToken(token);

        PasswordResetToken resetToken = new PasswordResetToken(
                hashedToken,
                user.getEmail(),
                Instant.now().plusSeconds(authProperties.getPasswordReset().getTokenExpiryHours() * 3600L)
        );

        long saveTokenStartTime = System.currentTimeMillis();
        log.debug("Attempting to save new password reset token for user: {}", sanitizeForLogging(user.getEmail()));
        tokenRepository.saveToken(resetToken);
        log.info("New password reset token for user {} saved in {}ms", sanitizeForLogging(user.getEmail()), System.currentTimeMillis() - saveTokenStartTime);

        sendPasswordResetEmail(user, token);

        eventPublisher.publishEvent(new PasswordResetRequestedEvent(
                sanitizeForLogging(user.getUsername()),
                sanitizeForLogging(user.getEmail())
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
            log.error("Failed to send password reset email to: {}", sanitizeForLogging(user.getEmail()));
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
                sanitizeForLogging(username),
                sanitizeForLogging(resetUrl),
                authProperties.getPasswordReset().getTokenExpiryHours(),
                sanitizeForLogging(authProperties.getEmail().getFromName())
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