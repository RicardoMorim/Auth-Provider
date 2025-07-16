package com.ricardo.auth.repository.refreshToken;

import com.ricardo.auth.domain.refreshtoken.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

/**
 * The interface Jpa refresh token repository.
 */
@NoRepositoryBean
public interface JpaRefreshTokenRepository
        extends RefreshTokenRepository, JpaRepository<RefreshToken, Long> {

    @Override
    default RefreshToken saveToken(RefreshToken refreshToken){
        return save(refreshToken);
    }

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.token = :token")
    Optional<RefreshToken> findByTokenRaw(@Param("token") String token);

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.token = :token AND rt.revoked = false AND rt.expiryDate > :now")
    Optional<RefreshToken> findValidToken(@Param("token") String token, @Param("now") Instant now);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.userEmail = :email")
    void revokeAllUserTokens(@Param("email") String email);

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

    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :now")
    int deleteExpiredTokens(@Param("now") Instant now);

    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken rt WHERE rt.userEmail = :userEmail")
    int deleteByUserEmail(@Param("userEmail") String userEmail);

    @Modifying
    @Transactional
    @Query(value = """
            DELETE FROM refresh_tokens 
            WHERE user_email = :userEmail 
            AND id IN (
                SELECT id FROM (
                    SELECT id FROM refresh_tokens 
                    WHERE user_email = :userEmail 
                    ORDER BY created_at ASC 
                    LIMIT GREATEST(0, (SELECT COUNT(*) FROM refresh_tokens WHERE user_email = :userEmail) - :maxTokens)
                ) AS oldest_tokens
            )
            """, nativeQuery = true)
    int deleteOldestTokensForUser(@Param("userEmail") String userEmail, @Param("maxTokens") int maxTokens);

    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.userEmail = :userEmail AND rt.expiryDate > :now AND rt.revoked = false")
    int countActiveTokensByUser(@Param("userEmail") String userEmail, @Param("now") Instant now);

    // Helper method for countActiveTokensByUser
    default int countActiveTokensByUser(String userEmail) {
        return countActiveTokensByUser(userEmail, Instant.now());
    }

    /**
     * Exists by token and revoked false and expiry date after boolean.
     *
     * @param token the token
     * @param now   the now
     * @return the boolean
     */
    @Query("SELECT COUNT(rt) > 0 FROM RefreshToken rt WHERE rt.token = :token AND rt.revoked = false AND rt.expiryDate > :now")
    boolean existsByTokenAndRevokedFalseAndExpiryDateAfter(@Param("token") String token, @Param("now") Instant now);
}