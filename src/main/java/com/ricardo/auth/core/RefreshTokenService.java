package com.ricardo.auth.core;

import com.ricardo.auth.domain.exceptions.TokenExpiredException;
import com.ricardo.auth.domain.refreshtoken.RefreshToken;
import com.ricardo.auth.domain.user.AuthUser;

/**
 * Service for managing refresh tokens in a JWT authentication system.
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 *
 * @param <U>  the AuthUser type parameter
 * @param <R>  the type parameter
 * @param <ID> the ID type parameter
 */
public interface RefreshTokenService<U extends AuthUser<ID, R>, R extends Role, ID> {

    /**
     * Creates a new refresh token for the specified user.
     *
     * @param user the user for whom to create the refresh token
     * @return the created refresh token
     */
    RefreshToken createRefreshToken(U user);

    /**
     * Verifies that the refresh token has not expired.
     *
     * @param token the refresh token to verify
     * @return the verified refresh token
     * @throws TokenExpiredException if the token has expired
     */
    RefreshToken verifyExpiration(RefreshToken token);

    /**
     * Revokes a specific refresh token.
     *
     * @param tokenValue the token value to revoke
     * @throws TokenExpiredException the token expired exception
     */
    void revokeToken(String tokenValue) throws TokenExpiredException;

    /**
     * Revokes all refresh tokens for a specific user.
     *
     * @param user the user whose tokens should be revoked
     */
    void revokeAllUserTokens(U user);

    /**
     * Retrieves the user associated with a refresh token.
     *
     * @param refreshToken the refresh token
     * @return the user associated with the token
     */
    U getUserFromRefreshToken(RefreshToken refreshToken);

    /**
     * Finds a refresh token by its value.
     *
     * @param tokenValue the token value
     * @return the refresh token
     * @throws TokenExpiredException the token expired exception
     */
    RefreshToken findByToken(String tokenValue) throws TokenExpiredException;

    /**
     * Cleans up expired refresh tokens.
     */
    void cleanupExpiredTokens();
}