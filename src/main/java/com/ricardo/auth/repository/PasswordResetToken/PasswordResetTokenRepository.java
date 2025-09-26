package com.ricardo.auth.repository.PasswordResetToken;

import com.ricardo.auth.domain.passwordresettoken.PasswordResetToken;
import org.springframework.data.repository.NoRepositoryBean;

import java.time.Instant;
import java.util.Optional;

/**
 * The interface Password reset token repository.
 */
@NoRepositoryBean
public interface PasswordResetTokenRepository {

    /**
     * Find by token and not used optional.
     *
     * @param token the token
     * @return the optional
     */
    Optional<PasswordResetToken> findByTokenAndNotUsed(String token);

    /**
     * Invalidate tokens for user.
     *
     * @param email the email
     * @param now   the now
     */
    void invalidateTokensForUser(String email, Instant now);

    /**
     * Count reset attempts for email since int.
     *
     * @param email the email
     * @param since the since
     * @return the int
     */
    int countResetAttemptsForEmailSince(String email, Instant since);

    /**
     * Save token password reset token.
     *
     * @param token the token
     * @return the password reset token
     */
    PasswordResetToken saveToken(PasswordResetToken token);

    /**
     * Delete expired tokens.
     *
     * @param before the before
     */
    void deleteExpiredTokens(Instant before);

    /**
     * Exists by token and not used boolean.
     *
     * @param token the token
     * @return the boolean
     */
    boolean existsByTokenAndNotUsed(String token);

    /**
     * Mark token as used.
     *
     * @param token  the token
     * @param usedAt the used at
     */
    void markTokenAsUsed(String token, Instant usedAt);

    /**
     * Find by token optional.
     *
     * @param token the token
     * @return the optional
     */
    default Optional<PasswordResetToken> findByToken(String token) {
        return findByTokenAndNotUsed(token);
    }

    /**
     * Exists by token boolean.
     *
     * @param token the token
     * @return the boolean
     */
    default boolean existsByToken(String token) {
        return existsByTokenAndNotUsed(token);
    }
}
