package com.ricardo.auth.service;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.RefreshTokenService;
import com.ricardo.auth.core.Role;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import com.ricardo.auth.domain.exceptions.TokenExpiredException;
import com.ricardo.auth.domain.refreshtoken.RefreshToken;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.repository.refreshToken.RefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

/**
 * Implementation of RefreshTokenService for managing refresh tokens.
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 *
 * @param <U>  the AuthUser type parameter
 * @param <R>  the type parameter
 * @param <ID> the ID type parameter
 */
public class RefreshTokenServiceImpl<U extends AuthUser<ID, R>, R extends Role, ID>
        implements RefreshTokenService<U, R, ID> {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenServiceImpl.class);
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserService<U, R, ID> userService;
    private final AuthProperties authProperties;

    /**
     * Instantiates a new Refresh token service.
     *
     * @param refreshTokenRepository the refresh token repository
     * @param userService            the user service
     * @param authProperties         the auth properties
     */
    public RefreshTokenServiceImpl(RefreshTokenRepository refreshTokenRepository,
                                   UserService<U, R, ID> userService,
                                   AuthProperties authProperties) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userService = userService;
        this.authProperties = authProperties;
    }

    @Override
    @Transactional
    public RefreshToken createRefreshToken(U user) {
        RefreshToken token = new RefreshToken(
                generateSecureToken(),
                user.getEmail(),
                calculateExpiry()
        );

        long startTime = System.currentTimeMillis();
        log.debug("Attempting to save refresh token for user: {}", user.getEmail());
        RefreshToken savedToken = refreshTokenRepository.saveToken(token);
        log.info("Refresh token for user {} saved successfully in {}ms", user.getEmail(), System.currentTimeMillis() - startTime);
        log.debug("Starting cleanup of oldest tokens for user: {}", user.getEmail());
        startTime = System.currentTimeMillis();
        cleanupOldestTokensForUser(user.getEmail());
        log.debug("Cleanup of oldest tokens for user {} completed. in {}ms", user.getEmail(), System.currentTimeMillis() - startTime);
        return savedToken;
    }

    @Override
    @Cacheable(value = "userByEmail", key = "#refreshToken.userEmail", condition = "#refreshToken != null")
    public U getUserFromRefreshToken(RefreshToken refreshToken) {
        String userEmail = refreshToken.getUserEmail();

        return userService.getUserByEmail(userEmail);
    }

    @Override
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().isBefore(Instant.now())) {
            throw new TokenExpiredException("Refresh token has expired");
        }
        return token;
    }

    @Override
    @CacheEvict(value = "refreshToken", key = "#tokenValue", condition = "#tokenValue != null")
    public void revokeToken(String tokenValue) {
        RefreshToken token = findByToken(tokenValue);
        token.setRevoked(true);
        long startTime = System.currentTimeMillis();
        log.debug("Attempting to revoke refresh token for user: {}", token.getUserEmail());
        refreshTokenRepository.saveToken(token);
        log.info("Refresh token for user {} revoked successfully in {}ms", token.getUserEmail(), System.currentTimeMillis() - startTime);
        log.info("Refresh token revoked for user: {}", token.getUserEmail());
    }

    @Override
    @CacheEvict(value = "userByEmail", key = "#user.email", condition = "#user != null")
    public void revokeAllUserTokens(U user) {
        long startTime = System.currentTimeMillis();
        log.debug("Attempting to revoke all refresh tokens for user: {}", user.getEmail());
        refreshTokenRepository.revokeAllUserTokens(user.getEmail());
        log.info("All refresh tokens for user {} revoked successfully in {}ms", user.getEmail(), System.currentTimeMillis() - startTime);
    }

    @Override
    @Cacheable(value = "refreshToken", key = "#tokenValue", condition = "#tokenValue != null")
    public RefreshToken findByToken(String tokenValue) {
        long startTime = System.currentTimeMillis();
        log.debug("Attempting to find refresh token by value");
        try {
            RefreshToken token = refreshTokenRepository.findByToken(tokenValue)
                    .orElseThrow(() -> new ResourceNotFoundException("Token not found"));
            log.info("Refresh token found successfully in {}ms", System.currentTimeMillis() - startTime);
            return token;
        } catch (Exception e) {
            log.error("Failed to find refresh token after {}ms. Error: {}", System.currentTimeMillis() - startTime, e.getMessage());
            throw e;
        }
    }

    @Override
    public void cleanupExpiredTokens() {
        Instant now = Instant.now();
        long startTime = System.currentTimeMillis();
        log.debug("Attempting to clean up expired refresh tokens");
        refreshTokenRepository.deleteExpiredTokens(now);
        log.info("Expired refresh tokens cleaned up successfully in {}ms", System.currentTimeMillis() - startTime);
    }

    /**
     * Generates a secure random token for use as a refresh token.
     *
     * @return a securely generated random token string
     */
    private String generateSecureToken() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[64];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private Instant calculateExpiry() {
        return Instant.now().plusMillis(authProperties.getJwt().getRefreshTokenExpiration());
    }

    /**
     * Cleanup old tokens when user exceeds max token limit
     *
     * @param userEmail the user email
     */
    @Transactional
    public void cleanupOldestTokensForUser(String userEmail) {
        int maxTokens = authProperties.getRefreshTokens().getMaxTokensPerUser();

        if (maxTokens <= 0) {
            return; // No limit configured
        }

        try {
            long startTime = System.currentTimeMillis();
            log.debug("Starting cleanup of oldest tokens for user: {}", userEmail);
            int deletedCount = refreshTokenRepository.deleteOldestTokensForUser(userEmail, maxTokens);
            log.info("Cleanup of oldest tokens for user {} completed in {}ms", userEmail, System.currentTimeMillis() - startTime);

            if (deletedCount > 0) {
                log.info("Cleaned up {} oldest tokens for user: {} (exceeded limit of {})",
                        deletedCount, userEmail, maxTokens);
            }
        } catch (Exception e) {
            log.error("Error cleaning up oldest tokens for user: {}", userEmail, e);
        }
    }

    @Override
    public void deleteAllTokens() {
        log.info("Deleting all refresh tokens");
        long startTime = System.currentTimeMillis();
        refreshTokenRepository.deleteAll();
        log.info("All refresh tokens deleted successfully in {}ms", System.currentTimeMillis() - startTime);
    }
}