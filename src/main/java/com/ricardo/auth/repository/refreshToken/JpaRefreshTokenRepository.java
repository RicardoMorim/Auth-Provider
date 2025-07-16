package com.ricardo.auth.repository.refreshToken;

import com.ricardo.auth.domain.tokenResponse.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Optional;

@NoRepositoryBean
public interface JpaRefreshTokenRepository
        extends RefreshTokenRepository, JpaRepository<RefreshToken, Long> {

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.token = :token")
    Optional<RefreshToken> findByTokenRaw(@Param("token") String token);

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.token = :token AND rt.revoked = false AND rt.expiryDate > :now")
    Optional<RefreshToken> findValidToken(@Param("token") String token, @Param("now") Instant now);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.userEmail = :email")
    void revokeAllUserTokens(@Param("email") String email);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :now")
    void deleteExpiredTokens(@Param("now") Instant now);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("DELETE FROM RefreshToken rt WHERE rt.userEmail = :userEmail AND rt.expiryDate < :expiryDate")
    void deleteByUserEmailAndExpiryDateBefore(@Param("userEmail") String userEmail, @Param("expiryDate") Instant expiryDate);

    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.userEmail = :userEmail AND rt.revoked = false AND rt.expiryDate > :now")
    long countByUserEmailAndRevokedFalseAndExpiryDateAfter(@Param("userEmail") String userEmail, @Param("now") Instant now);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("DELETE FROM RefreshToken rt WHERE rt.token = :token")
    void deleteByToken(@Param("token") String token);

    @Override
    default Optional<RefreshToken> findByToken(String token) {
        return findValidToken(token, Instant.now());
    }

    @Override
    default boolean existsByToken(String token) {
        return existsByTokenAndRevokedFalseAndExpiryDateAfter(token, Instant.now());
    }

    @Query("SELECT COUNT(rt) > 0 FROM RefreshToken rt WHERE rt.token = :token AND rt.revoked = false AND rt.expiryDate > :now")
    boolean existsByTokenAndRevokedFalseAndExpiryDateAfter(@Param("token") String token, @Param("now") Instant now);
}