package com.ricardo.auth.service;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.RefreshTokenService;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import com.ricardo.auth.domain.exceptions.TokenExpiredException;
import com.ricardo.auth.domain.refreshtoken.RefreshToken;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.repository.refreshToken.RefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * Implementation of RefreshTokenService for managing refresh tokens.
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 *
 * @param <U>  the AuthUser type parameter
 * @param <ID> the ID type parameter
 */
public class RefreshTokenServiceImpl<U extends AuthUser<?>, ID>
        implements RefreshTokenService<U, ID> {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserService<U, ID> userService;
    private final AuthProperties authProperties;

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenServiceImpl.class);

    /**
     * Instantiates a new Refresh token service.
     *
     * @param refreshTokenRepository the refresh token repository
     * @param userService            the user service
     * @param expiryDuration         the expiry duration in seconds
     */
    public RefreshTokenServiceImpl(RefreshTokenRepository refreshTokenRepository,
                                   UserService<U, ID> userService,
                                   AuthProperties authProperties) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userService = userService;
        this.authProperties = authProperties;
    }

    @Override
    public RefreshToken createRefreshToken(U user) {
        cleanupOldestTokensForUser(user.getEmail());

        RefreshToken token = new RefreshToken(
                generateSecureToken(),
                user.getEmail(),
                calculateExpiry()
        );

        return refreshTokenRepository.saveToken(token);
    }

    @Override
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
    public void revokeToken(String tokenValue) {
        RefreshToken token = findByToken(tokenValue);
        token.setRevoked(true);
        refreshTokenRepository.saveToken(token);
        log.info("Refresh token revoked for user: {}", token.getUserEmail());
    }

    @Override
    public void revokeAllUserTokens(U user) {
        refreshTokenRepository.revokeAllUserTokens(user.getEmail());
    }

    @Override
    public RefreshToken findByToken(String tokenValue) {
        return refreshTokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> new ResourceNotFoundException("Token not found"));
    }

    @Override
    public void cleanupExpiredTokens() {
        Instant now = Instant.now();
        refreshTokenRepository.deleteExpiredTokens(now);
    }

    private String generateSecureToken() {
        return UUID.randomUUID().toString() + "-" + System.currentTimeMillis();
    }

    private Instant calculateExpiry() {
        return Instant.now().plusMillis(authProperties.getJwt().getRefreshTokenExpiration());
    }

    /**
     * Cleanup old tokens when user exceeds max token limit
     */
    @Transactional
    public void cleanupOldestTokensForUser(String userEmail) {
        int maxTokens = authProperties.getRefreshTokens().getMaxTokensPerUser();

        if (maxTokens <= 0) {
            return; // No limit configured
        }

        try {
            int deletedCount = refreshTokenRepository.deleteOldestTokensForUser(userEmail, maxTokens);

            if (deletedCount > 0) {
                log.info("Cleaned up {} oldest tokens for user: {} (exceeded limit of {})",
                        deletedCount, userEmail, maxTokens);
            }
        } catch (Exception e) {
            log.error("Error cleaning up oldest tokens for user: {}", userEmail, e);
        }
    }
}