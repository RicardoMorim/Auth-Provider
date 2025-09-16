package com.ricardo.auth.domain.passwordresettoken;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for PasswordResetToken domain entity.
 * Tests business logic and validation methods.
 *
 * @since 3.1.0
 */
class PasswordResetTokenTest {

    /**
     * Constructor with valid parameters should create token.
     */
    @Test
    void constructor_WithValidParameters_ShouldCreateToken() {
        // Given
        String token = "test-token";
        UUID userId = UUID.randomUUID();
        Instant expiryDate = Instant.now().plusSeconds(3600);

        // When
        PasswordResetToken resetToken = new PasswordResetToken(token, "random-email@email.com", expiryDate);

        // Then
        assertThat(resetToken.getToken()).isEqualTo(token);
        assertThat(resetToken.getEmail()).isEqualTo("random-email@email.com");
        assertThat(resetToken.getExpiryDate()).isEqualTo(expiryDate);
        assertThat(resetToken.isUsed()).isFalse();
        assertThat(resetToken.getUsedAt()).isNull();
        assertThat(resetToken.getCreatedAt()).isNotNull();
    }

    /**
     * Is expired with future expiry date should return false.
     */
    @Test
    void isExpired_WithFutureExpiryDate_ShouldReturnFalse() {
        // Given
        PasswordResetToken token = new PasswordResetToken(
                "test-token",
                "email@email.com",
                Instant.now().plusSeconds(3600) // 1 hour in future
        );

        // When
        boolean expired = token.isExpired();

        // Then
        assertThat(expired).isFalse();
    }

    /**
     * Is expired with past expiry date should return true.
     */
    @Test
    void isExpired_WithPastExpiryDate_ShouldReturnTrue() {
        // Given
        PasswordResetToken token = new PasswordResetToken(
                "test-token",
                "email@email.com",
                Instant.now().minusSeconds(3600) // 1 hour in past
        );

        // When
        boolean expired = token.isExpired();

        // Then
        assertThat(expired).isTrue();
    }

    /**
     * Is valid with valid unused token should return true.
     */
    @Test
    void isValid_WithValidUnusedToken_ShouldReturnTrue() {
        // Given
        PasswordResetToken token = new PasswordResetToken(
                "test-token",
                "email@email.com",
                Instant.now().plusSeconds(3600)
        );

        // When
        boolean valid = token.isValid();

        // Then
        assertThat(valid).isTrue();
    }

    /**
     * Is valid with used token should return false.
     */
    @Test
    void isValid_WithUsedToken_ShouldReturnFalse() {
        // Given
        PasswordResetToken token = new PasswordResetToken(
                "test-token",
                "email@email.com",
                Instant.now().plusSeconds(3600)
        );
        token.setUsed(true);
        token.setUsedAt(Instant.now());

        // When
        boolean valid = token.isValid();

        // Then
        assertThat(valid).isFalse();
    }

    /**
     * Is valid with expired token should return false.
     */
    @Test
    void isValid_WithExpiredToken_ShouldReturnFalse() {
        // Given
        PasswordResetToken token = new PasswordResetToken(
                "test-token",
                "email@email.com",
                Instant.now().minusSeconds(3600)
        );

        // When
        boolean valid = token.isValid();

        // Then
        assertThat(valid).isFalse();
    }

    /**
     * Is valid with used and expired token should return false.
     */
    @Test
    void isValid_WithUsedAndExpiredToken_ShouldReturnFalse() {
        // Given
        PasswordResetToken token = new PasswordResetToken(
                "test-token",
                "email@email.com",
                Instant.now().minusSeconds(3600)
        );
        token.setUsed(true);
        token.setUsedAt(Instant.now());

        // When
        boolean valid = token.isValid();

        // Then
        assertThat(valid).isFalse();
    }

    /**
     * Sets used should update used status.
     */
    @Test
    void setUsed_ShouldUpdateUsedStatus() {
        // Given
        PasswordResetToken token = new PasswordResetToken(
                "test-token",
                "email@email.com",
                Instant.now().plusSeconds(3600)
        );

        // When
        token.setUsed(true);
        token.setUsedAt(Instant.now());

        // Then
        assertThat(token.isUsed()).isTrue();
        assertThat(token.getUsedAt()).isNotNull();
    }


    /**
     * Created at should be set on creation.
     */
    @Test
    void createdAt_ShouldBeSetOnCreation() {
        // Given
        Instant beforeCreation = Instant.now();

        // When
        PasswordResetToken token = new PasswordResetToken(
                "test-token",
                "email@email.com",
                Instant.now().plusSeconds(3600)
        );

        // Then
        Instant afterCreation = Instant.now();
        assertThat(token.getCreatedAt()).isBetween(beforeCreation, afterCreation);
    }

    /**
     * To string should not expose token.
     */
    @Test
    void toString_ShouldNotExposeToken() {
        // Given
        PasswordResetToken token = new PasswordResetToken(
                "secret-token",
                "email@email.com",
                Instant.now().plusSeconds(3600)
        );

        // When
        String tokenString = token.toString();

        // Then
        // Ensure sensitive information is not exposed in toString
        assertThat(tokenString).doesNotContain("secret-token");
        assertThat(tokenString).contains("PasswordResetToken");
    }

    /**
     * Equals with same id should return true.
     */
    @Test
    void equals_WithSameId_ShouldReturnTrue() {
        // Given
        UUID commonId = UUID.randomUUID();
        PasswordResetToken token1 = new PasswordResetToken("test-token", "email@email.com", Instant.now().plusSeconds(3600));
        token1.setId(commonId);

        PasswordResetToken token2 = new PasswordResetToken("test-token", "email@email.com", Instant.now().plusSeconds(3600));
        token2.setId(commonId);

        // When & Then
        assertThat(token1).isEqualTo(token2);
        assertThat(token1.hashCode()).isEqualTo(token2.hashCode());
    }

    /**
     * Equals with different id should return false.
     */
    @Test
    void equals_WithDifferentId_ShouldReturnFalse() {
        // Given
        PasswordResetToken token1 = new PasswordResetToken("token", "email@email.com", Instant.now().plusSeconds(3600));

        PasswordResetToken token2 = new PasswordResetToken("token", "email@email.com", Instant.now().plusSeconds(3600));

        token1.setId(UUID.randomUUID());
        token2.setId(UUID.randomUUID());
        // When & Then
        assertThat(token1).isNotEqualTo(token2);
    }
}
