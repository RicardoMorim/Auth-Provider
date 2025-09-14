package com.ricardo.auth.repository.PasswordResetToken;

import com.ricardo.auth.domain.passwordresettoken.PasswordResetToken;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface PasswordResetTokenRepository {

    Optional<PasswordResetToken> findByTokenAndNotUsed(String token);

    void invalidateTokensForUser(String email, Instant now);

    int countResetAttemptsForEmailSince(String email, Instant since);

    PasswordResetToken saveToken(PasswordResetToken token);

    void deleteExpiredTokens(Instant before);

    boolean existsByTokenAndNotUsed(String token);

    void markTokenAsUsed(String token, Instant usedAt);

    default Optional<PasswordResetToken> findByToken(String token) {
        return findByTokenAndNotUsed(token);
    }

    default boolean existsByToken(String token) {
        return existsByTokenAndNotUsed(token);
    }
}
