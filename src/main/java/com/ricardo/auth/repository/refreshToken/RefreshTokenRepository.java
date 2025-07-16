package com.ricardo.auth.repository.refreshToken;


import com.ricardo.auth.domain.tokenResponse.RefreshToken;
import org.springframework.data.repository.NoRepositoryBean;

import java.time.Instant;
import java.util.Optional;

@NoRepositoryBean
public interface RefreshTokenRepository {

    // Notice: NOT generic... refresh tokens are infrastructure
    // They store user EMAIL (string) instead of user object
    // This ensures it works with any AuthUser implementation and avoids polymorphism rabbit holes


    /**
     * Find ANY refresh token by its value. (Should only be used for admin operations/testing)
     *
     * @param token
     * @return Optional containing the RefreshToken if found, otherwise empty.
     */
    Optional<RefreshToken> findByTokenRaw(String token);



    /**
     * Find only VALID refresh token by its value.
     *
     * @param token
     * @return Optional containing the RefreshToken if found and valid, otherwise empty.
     */
    Optional<RefreshToken> findByToken(String token);

    Optional<RefreshToken> findValidToken(String token, Instant now);

    void deleteExpiredTokens(Instant now);

    void revokeAllUserTokens(String userEmail);


    RefreshToken save(RefreshToken refreshToken);

    void deleteByToken(String token);

    boolean existsByToken(String token);

    void deleteByUserEmailAndExpiryDateBefore(String userEmail, Instant now);
    long countByUserEmailAndRevokedFalseAndExpiryDateAfter(String userEmail, Instant now);

}