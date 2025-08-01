package com.ricardo.auth.service;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.repository.refreshToken.RefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * The type Refresh token cleanup service.
 */
@Service
@ConditionalOnProperty(prefix = "ricardo.auth.refresh-tokens", name = "enabled", havingValue = "true")
public class RefreshTokenCleanupService {

    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenCleanupService.class);

    private final RefreshTokenRepository refreshTokenRepository;
    private final AuthProperties authProperties;

    /**
     * Instantiates a new Refresh token cleanup service.
     *
     * @param refreshTokenRepository the refresh token repository
     * @param authProperties         the auth properties
     */
    public RefreshTokenCleanupService(RefreshTokenRepository refreshTokenRepository,
                                      AuthProperties authProperties) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.authProperties = authProperties;
    }

    /**
     * Scheduled cleanup of expired refresh tokens.
     * Runs based on the configured cleanup interval.
     */
    @Scheduled(fixedRateString = "#{${ricardo.auth.refresh-tokens.cleanup-interval:3600000}}")
    @Transactional
    public void cleanupExpiredTokens() {
        if (!authProperties.getRefreshTokens().isAutoCleanup()) {
            return;
        }
        logger.debug("Starting scheduled cleanup of expired refresh tokens");

        try {
            int deletedCount = refreshTokenRepository.deleteExpiredTokens(Instant.now());

            if (deletedCount > 0) {
                logger.info("Cleaned up {} expired refresh tokens", deletedCount);
            } else {
                logger.debug("No expired refresh tokens found during cleanup");
            }

        } catch (Exception e) {
            logger.error("Error during refresh token cleanup", e);
        }
    }
}