package com.ricardo.auth.repository.refreshToken;


import com.ricardo.auth.domain.tokenResponse.RefreshToken;
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
     */
    void deleteExpiredTokens(Instant now);

    /**
     * Revoke all user tokens.
     *
     * @param userEmail the user email
     */
    void revokeAllUserTokens(String userEmail);


    /**
     * Save refresh token.
     *
     * @param refreshToken the refresh token
     * @return the refresh token
     */
    RefreshToken save(RefreshToken refreshToken);

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

}