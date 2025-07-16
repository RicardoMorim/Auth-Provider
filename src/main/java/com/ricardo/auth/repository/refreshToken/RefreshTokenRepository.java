package com.ricardo.auth.repository.refreshToken;


import com.ricardo.auth.domain.refreshtoken.RefreshToken;
import org.springframework.data.repository.NoRepositoryBean;

import java.time.Instant;
import java.util.Optional;

/**
 * The interface Refresh token repository.
 */
@NoRepositoryBean
public interface RefreshTokenRepository {

    // Notice: NOT generic... refresh tokens are infrastructure
    // They store user EMAIL (string) instead of user object
    // This ensures it works with any AuthUser implementation and avoids polymorphism rabbit holes

    /**
     * Create a new refresh token for the user.
     *
     * @param refreshToken the refresh token to save
     * @return the refresh token
     */
    RefreshToken saveToken(RefreshToken refreshToken);

    /**
     * Find ANY refresh token by its value. (Should only be used for admin operations/testing)
     *
     * @param token the token
     * @return Optional containing the RefreshToken if found, otherwise empty.
     */
    Optional<RefreshToken> findByTokenRaw(String token);


    /**
     * Find only VALID refresh token by its value.
     *
     * @param token the token
     * @return Optional containing the RefreshToken if found and valid, otherwise empty.
     */
    Optional<RefreshToken> findByToken(String token);

    /**
     * Find valid token optional.
     *
     * @param token the token
     * @param now   the now
     * @return the optional
     */
    Optional<RefreshToken> findValidToken(String token, Instant now);

    /**
     * Delete expired tokens.
     *
     * @param now the now
     * @return the int
     */
    int deleteExpiredTokens(Instant now);

    /**
     * Revoke all user tokens.
     *
     * @param userEmail the user email
     */
    void revokeAllUserTokens(String userEmail);


    /**
     * Delete by token.
     *
     * @param token the token
     */
    void deleteByToken(String token);

    /**
     * Exists by token boolean.
     *
     * @param token the token
     * @return the boolean
     */
    boolean existsByToken(String token);

    /**
     * Delete by user email and expiry date before.
     *
     * @param userEmail the user email
     * @param now       the now
     */
    void deleteByUserEmailAndExpiryDateBefore(String userEmail, Instant now);

    /**
     * Count by user email and revoked false and expiry date after long.
     *
     * @param userEmail the user email
     * @param now       the now
     * @return the long
     */
    long countByUserEmailAndRevokedFalseAndExpiryDateAfter(String userEmail, Instant now);

    /**
     * Delete all tokens for a specific user
     *
     * @param userEmail user's email
     * @return number of deleted tokens
     */
    int deleteByUserEmail(String userEmail);

    /**
     * Delete oldest tokens for a user when they exceed the limit
     *
     * @param userEmail user's email
     * @param maxTokens maximum allowed tokens per user
     * @return number of deleted tokens
     */
    int deleteOldestTokensForUser(String userEmail, int maxTokens);

    /**
     * Count active tokens for a user
     *
     * @param userEmail user's email
     * @return number of active tokens
     */
    int countActiveTokensByUser(String userEmail);

    /**
     * Delete all.
     */
    void deleteAll();
}