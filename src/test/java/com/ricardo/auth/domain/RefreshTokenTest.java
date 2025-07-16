package com.ricardo.auth.domain;

import com.ricardo.auth.domain.tokenResponse.RefreshToken;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for RefreshToken entity.
 * Tests entity behavior, validation, and business logic.
 */
@SpringBootTest
@ActiveProfiles("test")
class RefreshTokenTest {

    /**
     * Should create refresh token with valid data.
     */
    @Test
    void shouldCreateRefreshToken_withValidData() {
        // Arrange
        String token = "test-token-123";
        String userEmail = "test@example.com";
        Instant expiryDate = Instant.now().plusSeconds(3600);

        // Act
        RefreshToken refreshToken = new RefreshToken(token, userEmail, expiryDate);

        // Assert
        assertNotNull(refreshToken);
        assertEquals(token, refreshToken.getToken());
        assertEquals(userEmail, refreshToken.getUserEmail());
        assertEquals(expiryDate, refreshToken.getExpiryDate());
        assertFalse(refreshToken.isRevoked());
    }


    /**
     * Is expired should return false when token is not expired.
     */
    @Test
    void isExpired_shouldReturnFalse_whenTokenIsNotExpired() {
        // Arrange
        RefreshToken validToken = new RefreshToken(
                "valid-token",
                "test@example.com",
                Instant.now().plusSeconds(3600) // 1 hour from now
        );

        // Act & Assert
        assertFalse(validToken.isExpired());
    }

    /**
     * Sets revoked should mark token as revoked.
     */
    @Test
    void setRevoked_shouldMarkTokenAsRevoked() {
        // Arrange
        RefreshToken token = new RefreshToken(
                "test-token",
                "test@example.com",
                Instant.now().plusSeconds(3600)
        );

        // Act
        token.setRevoked(true);

        // Assert
        assertTrue(token.isRevoked());
    }

    /**
     * Should handle edge case expiration times.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    void shouldHandleEdgeCaseExpirationTimes() throws InterruptedException {
        // Test exact moment of expiry
        RefreshToken tokenAtExpiryMoment = new RefreshToken(
                "token-at-expiry",
                "test@example.com",
                Instant.now()
        );

        Thread.sleep(100); // Sleep for a short time to ensure we cross the boundary

        // Should be considered expired at exactly the expiry time
        assertTrue(tokenAtExpiryMoment.isExpired());
    }

    /**
     * Should handle null values.
     */
    @Test
    void shouldHandleNullValues() {
        // Act & Assert - Should handle nulls gracefully
        assertThrows(IllegalArgumentException.class, () -> {
            new RefreshToken(null, null, null);
        });
    }

    /**
     * Should support token with long values.
     */
    @Test
    void shouldSupportTokenWithLongValues() {
        // Arrange - Very long token and email
        String longToken = "a".repeat(1000);
        String longEmail = "very.long.email.address.for.testing.purposes@example.com";

        // Act
        RefreshToken token = new RefreshToken(longToken, longEmail, Instant.now().plusSeconds(3600));

        // Assert
        assertEquals(longToken, token.getToken());
        assertEquals(longEmail, token.getUserEmail());
    }
}