package com.ricardo.auth.repository.PasswordResetToken;

import com.ricardo.auth.domain.passwordresettoken.PasswordResetToken;
import com.ricardo.auth.domain.user.Email;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@NoRepositoryBean
public interface JpaPasswordResetTokenRepository extends PasswordResetTokenRepository, JpaRepository<PasswordResetToken, UUID> {

    @Query("SELECT t FROM PasswordResetToken t WHERE t.token = :token AND t.used = false AND t.expiryDate > :now")
    Optional<PasswordResetToken> findByTokenAndNotUsed(@Param("token") String token, @Param("now") Instant now);

    @Modifying
    @Query("UPDATE PasswordResetToken t SET t.used = true, t.usedAt = :now WHERE t.userId = :userId AND t.used = false")
    void invalidateTokensForUser(@Param("userId") UUID userId, @Param("now") Instant now);


    @Query("""
                SELECT COUNT(t)
                FROM PasswordResetToken t
                JOIN User u ON t.userId = u.id
                WHERE u.email = :email
                  AND t.createdAt > :since
            """)
    int countResetAttemptsForEmailSinceInternal(@Param("email") Email email,
                                                @Param("since") Instant since);

    default int countResetAttemptsForEmailSince(String email, Instant since) {
        return countResetAttemptsForEmailSinceInternal(Email.valueOf(email), since);
    }

    @Modifying
    @Query("DELETE FROM PasswordResetToken t WHERE t.expiryDate < :before OR t.used = true")
    void deleteExpiredTokens(@Param("before") Instant before);

    @Query("SELECT COUNT(t) > 0 FROM PasswordResetToken t WHERE t.token = :token AND t.used = false AND t.expiryDate > :now")
    boolean existsByTokenAndNotUsed(@Param("token") String token, @Param("now") Instant now);

    @Modifying
    @Query("UPDATE PasswordResetToken t SET t.used = true, t.usedAt = :usedAt WHERE t.token = :token")
    void markTokenAsUsed(@Param("token") String token, @Param("usedAt") Instant usedAt);

    // Override default methods to include current time
    @Override
    default Optional<PasswordResetToken> findByTokenAndNotUsed(String token) {
        return findByTokenAndNotUsed(token, Instant.now());
    }

    @Override
    default boolean existsByTokenAndNotUsed(String token) {
        return existsByTokenAndNotUsed(token, Instant.now());
    }

    @Override
    default PasswordResetToken saveToken(PasswordResetToken token) {
        return save(token);
    }

    @Override
    default int countResetAttemptsForIpSince(String ipAddress, Instant since) {
        // JPA implementation doesn't track IP addresses by default
        return 0;
    }
}

