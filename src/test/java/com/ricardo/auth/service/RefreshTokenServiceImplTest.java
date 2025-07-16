package com.ricardo.auth.service;

import com.ricardo.auth.core.RefreshTokenService;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import com.ricardo.auth.domain.exceptions.TokenExpiredException;
import com.ricardo.auth.domain.tokenResponse.RefreshToken;
import com.ricardo.auth.domain.user.*;
import com.ricardo.auth.repository.refreshToken.RefreshTokenRepository;
import com.ricardo.auth.repository.user.DefaultUserJpaRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for RefreshTokenServiceImpl.
 * Tests the complete refresh token workflow with real database and services.
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class RefreshTokenServiceImplTest {

    @Autowired
    private RefreshTokenService<User, Long> refreshTokenService;

    @Autowired
    private UserService<User, Long> userService;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private DefaultUserJpaRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private User testUser;

    @BeforeEach
    void setUp() {
        // Clean database
        userRepository.deleteAll();

        // Create test user
        testUser = new User(
                Username.valueOf("testuser"),
                Email.valueOf("test@example.com"),
                Password.fromHash(passwordEncoder.encode("Password@123"))
        );
        testUser.addRole(AppRole.USER);
        testUser = userRepository.save(testUser);
    }

    // ========== CREATE REFRESH TOKEN TESTS ==========

    @Test
    void createRefreshToken_shouldCreateValidToken_whenUserExists() {
        // Act
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(testUser);

        // Assert
        assertNotNull(refreshToken);
        assertNotNull(refreshToken.getToken());
        assertEquals(testUser.getEmail(), refreshToken.getUserEmail());
        assertTrue(refreshToken.getExpiryDate().isAfter(Instant.now()));
        assertFalse(refreshToken.isRevoked());
        assertFalse(refreshToken.isExpired());
    }

    @Test
    void createRefreshToken_shouldGenerateUniqueTokens_whenCalledMultipleTimes() {
        // Act
        RefreshToken token1 = refreshTokenService.createRefreshToken(testUser);
        RefreshToken token2 = refreshTokenService.createRefreshToken(testUser);

        // Assert
        assertNotEquals(token1.getToken(), token2.getToken());
        assertEquals(token1.getUserEmail(), token2.getUserEmail());
    }

    @Test
    void createRefreshToken_shouldCleanupExpiredTokens_beforeCreatingNew() {
        // Arrange - Create an expired token manually
        RefreshToken expiredToken = new RefreshToken(
                "expired-token-123",
                testUser.getEmail(),
                Instant.now().plusSeconds(1) // 1 second in the future
        );
        refreshTokenRepository.save(expiredToken);

        // Simulate waiting for the token to expire
        try {
            Thread.sleep(2000); // Wait 2 seconds to ensure the token is expired
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Act
        RefreshToken newToken = refreshTokenService.createRefreshToken(testUser);

        // Assert
        assertNotNull(newToken);
        assertNotEquals("expired-token-123", newToken.getToken());
    }

    // ========== VERIFY EXPIRATION TESTS ==========

    @Test
    void verifyExpiration_shouldReturnToken_whenTokenIsValid() {
        // Arrange
        RefreshToken validToken = refreshTokenService.createRefreshToken(testUser);

        // Act
        RefreshToken result = refreshTokenService.verifyExpiration(validToken);

        // Assert
        assertEquals(validToken, result);
        assertFalse(result.isExpired());
    }

    @Test
    void verifyExpiration_shouldThrowException_whenTokenIsExpired() {
        // Act & Assert
        TokenExpiredException exception = assertThrows(TokenExpiredException.class, () -> {
            new RefreshToken(
                    "expired-token",
                    testUser.getEmail(),
                    Instant.now().minusSeconds(3600) // 1 hour ago
            );
        });

        assertEquals("Expiration must be a future date", exception.getMessage());
    }

    // ========== FIND BY TOKEN TESTS ==========

    @Test
    void findByToken_shouldReturnToken_whenTokenExists() {
        // Arrange
        RefreshToken createdToken = refreshTokenService.createRefreshToken(testUser);

        // Act
        RefreshToken foundToken = refreshTokenService.findByToken(createdToken.getToken());

        // Assert
        assertNotNull(foundToken);
        assertEquals(createdToken.getToken(), foundToken.getToken());
        assertEquals(createdToken.getUserEmail(), foundToken.getUserEmail());
    }

    @Test
    void findByToken_shouldThrowException_whenTokenNotFound() {
        // Act & Assert
        assertThrows(ResourceNotFoundException.class, () -> {
            refreshTokenService.findByToken("non-existent-token");
        });
    }

    // ========== GET USER FROM REFRESH TOKEN TESTS ==========

    @Test
    void getUserFromRefreshToken_shouldReturnUser_whenTokenIsValid() {
        // Arrange
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(testUser);

        // Act
        User result = refreshTokenService.getUserFromRefreshToken(refreshToken);

        // Assert
        assertNotNull(result);
        assertEquals(testUser.getId(), result.getId());
        assertEquals(testUser.getEmail(), result.getEmail());
        assertEquals(testUser.getUsername(), result.getUsername());
    }

    @Test
    void getUserFromRefreshToken_shouldThrowException_whenUserNotFound() {
        // Arrange - Create token for non-existent user
        RefreshToken orphanToken = new RefreshToken(
                "orphan-token",
                "nonexistent@example.com",
                Instant.now().plusSeconds(3600)
        );

        // Act & Assert
        assertThrows(ResourceNotFoundException.class, () -> {
            refreshTokenService.getUserFromRefreshToken(orphanToken);
        });
    }

    // ========== REVOKE TOKEN TESTS ==========

    @Test
    void revokeToken_shouldMarkTokenAsRevoked_whenTokenExists() {
        // Arrange
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(testUser);
        String tokenValue = refreshToken.getToken();

        // Act
        refreshTokenService.revokeToken(tokenValue);

        // Assert - Use raw find to get revoked token
        RefreshToken revokedToken = refreshTokenRepository.findByTokenRaw(tokenValue)
                .orElseThrow(() -> new AssertionError("Token should exist"));
        assertTrue(revokedToken.isRevoked());

        // Assert - findByToken should NOT return revoked token
        assertThrows(ResourceNotFoundException.class, () -> {
            refreshTokenService.findByToken(tokenValue);
        });
    }

    @Test
    void revokeToken_shouldThrowException_whenTokenNotFound() {
        // Act & Assert
        assertThrows(ResourceNotFoundException.class, () -> {
            refreshTokenService.revokeToken("non-existent-token");
        });
    }

    // ========== REVOKE ALL USER TOKENS TESTS ==========

    @Test
    void revokeAllUserTokens_shouldRevokeAllTokensForUser() {
        // Arrange
        RefreshToken token1 = refreshTokenService.createRefreshToken(testUser);
        RefreshToken token2 = refreshTokenService.createRefreshToken(testUser);

        // Store the token values for later lookup
        String token1Value = token1.getToken();
        String token2Value = token2.getToken();

        // Act
        refreshTokenService.revokeAllUserTokens(testUser);

        // Assert - Fetch fresh objects from database (not the stale in-memory ones)
        RefreshToken revokedToken1 = refreshTokenRepository.findByTokenRaw(token1Value)
                .orElseThrow(() -> new AssertionError("Token should exist"));
        RefreshToken revokedToken2 = refreshTokenRepository.findByTokenRaw(token2Value)
                .orElseThrow(() -> new AssertionError("Token should exist"));

        assertTrue(revokedToken1.isRevoked());
        assertTrue(revokedToken2.isRevoked());

        // Assert - findByToken should NOT return revoked tokens
        assertThrows(ResourceNotFoundException.class, () -> {
            refreshTokenService.findByToken(token1Value);
        });
        assertThrows(ResourceNotFoundException.class, () -> {
            refreshTokenService.findByToken(token2Value);
        });
    }

    // ========== CLEANUP TESTS ==========

    @Test
    void cleanupExpiredTokens_shouldRemoveExpiredTokens() throws InterruptedException {
        // Arrange - Create expired and valid tokens
        RefreshToken expiredToken = new RefreshToken(
                "expired-token",
                testUser.getEmail(),
                Instant.now().plusSeconds(1)
        );
        refreshTokenRepository.save(expiredToken);

        RefreshToken validToken = refreshTokenService.createRefreshToken(testUser);

        // Act
        refreshTokenService.cleanupExpiredTokens();

        // Assert - Valid token should still exist, expired should be gone
        assertDoesNotThrow(() -> refreshTokenService.findByToken(validToken.getToken()));

        Thread.sleep(1050);
        assertThrows(ResourceNotFoundException.class, () -> {
            refreshTokenService.findByToken("expired-token");
        });
    }

    // ========== BUSINESS LOGIC TESTS ==========

    @Test
    void shouldHandleMultipleUsersWithSeparateTokens() {
        // Arrange - Create second user
        User secondUser = new User(
                Username.valueOf("seconduser"),
                Email.valueOf("second@example.com"),
                Password.fromHash(passwordEncoder.encode("Password@456"))
        );
        secondUser.addRole(AppRole.USER);
        secondUser = userRepository.save(secondUser);

        // Act - Create tokens for both users
        RefreshToken token1 = refreshTokenService.createRefreshToken(testUser);
        RefreshToken token2 = refreshTokenService.createRefreshToken(secondUser);

        // Assert - Tokens should be separate
        assertNotEquals(token1.getToken(), token2.getToken());
        assertEquals(testUser.getEmail(), token1.getUserEmail());
        assertEquals(secondUser.getEmail(), token2.getUserEmail());

        // Users should be correctly resolved
        User resolvedUser1 = refreshTokenService.getUserFromRefreshToken(token1);
        User resolvedUser2 = refreshTokenService.getUserFromRefreshToken(token2);

        assertEquals(testUser.getId(), resolvedUser1.getId());
        assertEquals(secondUser.getId(), resolvedUser2.getId());
    }

    @Test
    void shouldMaintainTokenLifecycleThroughUserOperations() {
        // Arrange
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(testUser);
        String originalToken = refreshToken.getToken();

        // Act - Update user (should not affect token)
        testUser.addRole(AppRole.ADMIN);
        userRepository.save(testUser);

        // Assert - Token should still work
        RefreshToken foundToken = refreshTokenService.findByToken(originalToken);
        User resolvedUser = refreshTokenService.getUserFromRefreshToken(foundToken);

        assertNotNull(foundToken);
        assertNotNull(resolvedUser);
        assertEquals(testUser.getId(), resolvedUser.getId());
        assertTrue(resolvedUser.getRoles().contains(AppRole.ADMIN));
    }
}