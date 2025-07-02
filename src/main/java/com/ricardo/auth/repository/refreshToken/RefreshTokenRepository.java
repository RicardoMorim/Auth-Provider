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

    Optional<RefreshToken> findByRefreshToken(String token);

    Optional<RefreshToken> findValidToken(String token, Instant now);

    void deleteExpiredTokens(Instant now);

    void revokeAllUserTokens(String userEmail);

    void deleteUserExpiredTokens(String userEmail);

    RefreshToken save(RefreshToken refreshToken);

    void deleteByRefreshToken(String token);

    boolean existsByRefreshToken(String token);

    long countActiveTokensByUserEmail(String userEmail);

}