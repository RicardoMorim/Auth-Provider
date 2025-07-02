package com.ricardo.auth.repository.refreshToken;

import com.ricardo.auth.domain.tokenResponse.RefreshToken;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
@ConditionalOnProperty(prefix = "ricardo.auth.refresh-tokens.storage",
        name = "type", havingValue = "jpa", matchIfMissing = true)
public interface DefaultRefreshTokenJpaRepository
        extends RefreshTokenRepository, JpaRepository<RefreshToken, Long> {

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.token = :token AND rt.revoked = false AND rt.expiryDate > :now")
    Optional<RefreshToken> findValidToken(@Param("token") String token, @Param("now") Instant now);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.userEmail = :email")
    void revokeAllUserTokens(@Param("email") String email);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :now")
    void deleteExpiredTokens(@Param("now") Instant now);

    @Override
    default Optional<RefreshToken> findByRefreshToken(String token) {
        return findValidToken(token, Instant.now());
    }

    @Override
    default boolean existsByRefreshToken(String token) {
        return existsByTokenAndRevokedFalse(token);
    }

    boolean existsByTokenAndRevokedFalse(String token);
    long countByUserEmailAndRevokedFalse(String userEmail);
    void deleteByToken(String token);
}