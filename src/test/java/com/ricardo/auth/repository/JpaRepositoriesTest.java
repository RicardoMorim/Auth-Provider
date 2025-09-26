package com.ricardo.auth.repository;

import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.domain.refreshtoken.RefreshToken;
import com.ricardo.auth.domain.user.Email;
import com.ricardo.auth.domain.user.Password;
import com.ricardo.auth.domain.user.User;
import com.ricardo.auth.domain.user.Username;
import com.ricardo.auth.repository.refreshToken.DefaultJpaRefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for JPA refresh token repository implementation.
 * Uses H2 in-memory database for testing.
 */
@DataJpaTest
@Import(TestJpaConfiguration.class)
@ActiveProfiles("test")
class JpaRepositoriesTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private DefaultJpaRefreshTokenRepository repository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private PasswordPolicyService passwordPolicyService;

    private User testUser;
    private User secondUser;

    /**
     * Sets up.
     */
    @BeforeEach
    void setUp() {

        repository.deleteAll();

        testUser = new User(
                Username.valueOf("testuser"),
                Email.valueOf("test@example.com"),
                Password.valueOf("TestPassword@123", passwordEncoder, passwordPolicyService)
        );

        secondUser = new User(
                Username.valueOf("testuser2"),
                Email.valueOf("test2@example.com"),
                Password.valueOf("TestPassword@123", passwordEncoder, passwordPolicyService)
        );

        // Persist users if needed for foreign key constraints
        entityManager.persistAndFlush(testUser);
        entityManager.persistAndFlush(secondUser);
    }

    /**
     * Should saveUser and retrieve refresh token.
     */
    @Test
    @DisplayName("Should saveUser and retrieve refresh token")
    void shouldSaveAndRetrieveRefreshToken() {
        // Arrange
        RefreshToken token = new RefreshToken(
                "test-token-123",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );

        // Act
        RefreshToken saved = repository.save(token);
        Optional<RefreshToken> found = repository.findByTokenRaw("test-token-123");

        // Assert
        assertThat(saved.getId()).isNotNull();
        assertThat(saved.getCreatedAt()).isNotNull();
        assertThat(found).isPresent();
        assertThat(found.get().getToken()).isEqualTo("test-token-123");
        assertThat(found.get().getUserEmail()).isEqualTo(testUser.getEmail());
        assertThat(found.get().getCreatedAt()).isNotNull();
    }

    /**
     * Should find valid token only.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    @DisplayName("Should find valid token only with findByToken")
    void shouldFindValidTokenOnly() throws InterruptedException {
        // Arrange - Create expired token
        RefreshToken expiredToken = new RefreshToken(
                "expired-token",
                testUser.getEmail(),
                Instant.now().plusSeconds(1)
        );
        entityManager.persistAndFlush(expiredToken);

        Thread.sleep(1050); // Wait for expiry

        // Arrange - Create valid token
        RefreshToken validToken = new RefreshToken(
                "valid-token",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        entityManager.persistAndFlush(validToken);

        // Act
        Optional<RefreshToken> expiredFound = repository.findByToken("expired-token");
        Optional<RefreshToken> validFound = repository.findByToken("valid-token");

        // Assert
        assertThat(expiredFound).isEmpty();
        assertThat(validFound).isPresent();
    }

    /**
     * Should not find revoked tokens with find by token.
     */
    @Test
    @DisplayName("Should not find revoked tokens with findByToken")
    void shouldNotFindRevokedTokensWithFindByToken() {
        // Arrange
        RefreshToken token = new RefreshToken(
                "revoked-token",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        token.setRevoked(true);
        entityManager.persistAndFlush(token);

        // Act
        Optional<RefreshToken> found = repository.findByToken("revoked-token");
        Optional<RefreshToken> foundRaw = repository.findByTokenRaw("revoked-token");

        // Assert
        assertThat(found).isEmpty();
        assertThat(foundRaw).isPresent();
        assertThat(foundRaw.get().isRevoked()).isTrue();
    }

    /**
     * Should find valid token with specific timestamp.
     */
    @Test
    @DisplayName("Should find valid token with specific timestamp")
    void shouldFindValidTokenWithSpecificTimestamp() {
        // Arrange
        Instant futureTime = Instant.now().plusSeconds(3600);
        RefreshToken token = new RefreshToken(
                "timestamp-token",
                testUser.getEmail(),
                futureTime
        );
        entityManager.persistAndFlush(token);

        // Act
        Optional<RefreshToken> found = repository.findValidToken("timestamp-token", Instant.now());

        // Assert
        assertThat(found).isPresent();
        assertThat(found.get().getExpiryDate()).isEqualTo(futureTime);
    }

    /**
     * Should revoke all user tokens.
     */
    @Test
    @DisplayName("Should revoke all user tokens")
    void shouldRevokeAllUserTokens() {
        // Arrange
        RefreshToken token1 = new RefreshToken(
                "token1",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        RefreshToken token2 = new RefreshToken(
                "token2",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        RefreshToken token3 = new RefreshToken(
                "token3",
                secondUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );

        entityManager.persistAndFlush(token1);
        entityManager.persistAndFlush(token2);
        entityManager.persistAndFlush(token3);

        // Act
        repository.revokeAllUserTokens(testUser.getEmail());
        entityManager.flush();
        entityManager.clear();

        // Assert
        Optional<RefreshToken> found1 = repository.findByTokenRaw("token1");
        Optional<RefreshToken> found2 = repository.findByTokenRaw("token2");
        Optional<RefreshToken> found3 = repository.findByTokenRaw("token3");

        assertThat(found1).isPresent();
        assertThat(found1.get().isRevoked()).isTrue();
        assertThat(found2).isPresent();
        assertThat(found2.get().isRevoked()).isTrue();
        assertThat(found3).isPresent();
        assertThat(found3.get().isRevoked()).isFalse(); // Different user
    }

    /**
     * Should delete expired tokens.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    @DisplayName("Should delete expired tokens")
    void shouldDeleteExpiredTokens() throws InterruptedException {
        // Arrange
        RefreshToken expiredToken1 = new RefreshToken(
                "expired-token-1",
                testUser.getEmail(),
                Instant.now().plusSeconds(1)
        );
        RefreshToken expiredToken2 = new RefreshToken(
                "expired-token-2",
                testUser.getEmail(),
                Instant.now().plusSeconds(1)
        );
        RefreshToken validToken = new RefreshToken(
                "valid-token",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );

        entityManager.persistAndFlush(expiredToken1);
        entityManager.persistAndFlush(expiredToken2);
        entityManager.persistAndFlush(validToken);

        Thread.sleep(1050); // Wait for expiry

        // Act
        int deletedCount = repository.deleteExpiredTokens(Instant.now());

        // Assert
        assertThat(deletedCount).isEqualTo(2);
        assertThat(repository.findByTokenRaw("expired-token-1")).isEmpty();
        assertThat(repository.findByTokenRaw("expired-token-2")).isEmpty();
        assertThat(repository.findByTokenRaw("valid-token")).isPresent();
    }

    /**
     * Should delete oldest tokens when user exceeds limit.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    @DisplayName("Should delete oldest tokens when user exceeds max limit")
    void shouldDeleteOldestTokensWhenUserExceedsLimit() throws InterruptedException {
        // Arrange - Create 5 tokens with different creation times
        String userEmail = testUser.getEmail();

        List<RefreshToken> tokens = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            RefreshToken token = new RefreshToken("token" + i, userEmail, Instant.now().plusSeconds(3600));
            tokens.add(entityManager.persistAndFlush(token));
            Thread.sleep(10); // Small delay to ensure different creation times
        }

        // Act - Keep only 3 tokens (should delete 2 oldest)
        int deletedCount = repository.deleteOldestTokensForUser(userEmail, 3);

        // Assert
        assertThat(deletedCount).isEqualTo(2);

        // Verify the oldest tokens were deleted
        assertThat(repository.findByTokenRaw("token0")).isEmpty();
        assertThat(repository.findByTokenRaw("token1")).isEmpty();

        // Verify the newest tokens still exist
        assertThat(repository.findByTokenRaw("token2")).isPresent();
        assertThat(repository.findByTokenRaw("token3")).isPresent();
        assertThat(repository.findByTokenRaw("token4")).isPresent();
    }

    /**
     * Should count active tokens for user.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    @DisplayName("Should count active tokens for user")
    void shouldCountActiveTokensForUser() throws InterruptedException {
        // Arrange
        RefreshToken activeToken1 = new RefreshToken(
                "active1",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        RefreshToken activeToken2 = new RefreshToken(
                "active2",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        RefreshToken expiredToken = new RefreshToken(
                "expired",
                testUser.getEmail(),
                Instant.now().plusSeconds(1)
        );
        RefreshToken revokedToken = new RefreshToken(
                "revoked",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        revokedToken.setRevoked(true);

        RefreshToken otherUserToken = new RefreshToken(
                "other",
                secondUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );

        entityManager.persistAndFlush(activeToken1);
        entityManager.persistAndFlush(activeToken2);
        entityManager.persistAndFlush(expiredToken);
        entityManager.persistAndFlush(revokedToken);
        entityManager.persistAndFlush(otherUserToken);

        Thread.sleep(1050); // Wait for expiry

        // Act
        int activeCount = repository.countActiveTokensByUser(testUser.getEmail());

        // Assert - Only 2 active tokens should be counted
        assertThat(activeCount).isEqualTo(2);
    }

    /**
     * Should verify jpa entity lifecycle callbacks.
     */
    @Test
    @DisplayName("Should handle JPA entity lifecycle callbacks")
    void shouldVerifyJpaEntityLifecycleCallbacks() {
        // Arrange
        String userEmail = testUser.getEmail();
        Instant beforeCreation = Instant.now();

        RefreshToken token = new RefreshToken("lifecycle-test", userEmail, Instant.now().plusSeconds(3600));

        // Act
        RefreshToken savedToken = entityManager.persistAndFlush(token);

        Instant afterCreation = Instant.now();

        // Assert
        assertThat(savedToken.getCreatedAt()).isNotNull();
        assertThat(savedToken.getCreatedAt()).isBetween(beforeCreation, afterCreation);
        assertThat(savedToken.getId()).isNotNull();
    }


    /**
     * Should delete tokens by user email and expiry date.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    @DisplayName("Should delete tokens by user email and expiry date")
    void shouldDeleteTokensByUserEmailAndExpiryDate() throws InterruptedException {
        // Arrange
        RefreshToken expiredToken = new RefreshToken(
                "expired-token",
                testUser.getEmail(),
                Instant.now().plusSeconds(1)
        );
        RefreshToken validToken = new RefreshToken(
                "valid-token",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );

        entityManager.persistAndFlush(expiredToken);
        entityManager.persistAndFlush(validToken);

        Thread.sleep(1050); // Wait for expiry

        // Act
        repository.deleteByUserEmailAndExpiryDateBefore(testUser.getEmail(), Instant.now());
        entityManager.flush();
        entityManager.clear();

        // Assert
        assertThat(repository.findByTokenRaw("expired-token")).isEmpty();
        assertThat(repository.findByTokenRaw("valid-token")).isPresent();
    }

    /**
     * Should count active tokens using jpa method.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    @DisplayName("Should count active tokens using JPA method")
    void shouldCountActiveTokensUsingJpaMethod() throws InterruptedException {
        // Arrange
        RefreshToken activeToken1 = new RefreshToken(
                "active1",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        RefreshToken activeToken2 = new RefreshToken(
                "active2",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        RefreshToken expiredToken = new RefreshToken(
                "expired",
                testUser.getEmail(),
                Instant.now().plusSeconds(1)
        );
        RefreshToken revokedToken = new RefreshToken(
                "revoked",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        revokedToken.setRevoked(true);

        RefreshToken otherUserToken = new RefreshToken(
                "other",
                secondUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );

        entityManager.persistAndFlush(activeToken1);
        entityManager.persistAndFlush(activeToken2);
        entityManager.persistAndFlush(expiredToken);
        entityManager.persistAndFlush(revokedToken);
        entityManager.persistAndFlush(otherUserToken);

        Thread.sleep(1050); // Wait for expiry

        // Act
        long count = repository.countByUserEmailAndRevokedFalseAndExpiryDateAfter(
                testUser.getEmail(),
                Instant.now()
        );

        // Assert - Only 2 active tokens should be counted
        assertThat(count).isEqualTo(2);
    }

    /**
     * Should delete token by token value.
     */
    @Test
    @DisplayName("Should delete token by token value")
    void shouldDeleteTokenByTokenValue() {
        // Arrange
        RefreshToken token = new RefreshToken(
                "delete-token",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        entityManager.persistAndFlush(token);

        // Act
        repository.deleteByToken("delete-token");
        entityManager.flush();
        entityManager.clear();

        // Assert
        assertThat(repository.findByTokenRaw("delete-token")).isEmpty();
    }

    /**
     * Should check token existence.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    @DisplayName("Should check token existence correctly")
    void shouldCheckTokenExistence() throws InterruptedException {
        // Arrange
        RefreshToken validToken = new RefreshToken(
                "exists-token",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        RefreshToken expiredToken = new RefreshToken(
                "expired-token",
                testUser.getEmail(),
                Instant.now().plusSeconds(1)
        );
        RefreshToken revokedToken = new RefreshToken(
                "revoked-token",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        revokedToken.setRevoked(true);

        entityManager.persistAndFlush(validToken);
        entityManager.persistAndFlush(expiredToken);
        entityManager.persistAndFlush(revokedToken);

        Thread.sleep(1050); // Wait for expiry

        // Act & Assert
        assertThat(repository.existsByToken("exists-token")).isTrue();
        assertThat(repository.existsByToken("expired-token")).isFalse();
        assertThat(repository.existsByToken("revoked-token")).isFalse();
        assertThat(repository.existsByToken("nonexistent-token")).isFalse();
    }

    /**
     * Should delete all tokens for user.
     */
    @Test
    @DisplayName("Should delete all tokens for a specific user")
    void shouldDeleteAllTokensForUser() {
        // Arrange
        RefreshToken token1 = new RefreshToken("token1", testUser.getEmail(), Instant.now().plusSeconds(3600));
        RefreshToken token2 = new RefreshToken("token2", testUser.getEmail(), Instant.now().plusSeconds(3600));
        RefreshToken token3 = new RefreshToken("token3", secondUser.getEmail(), Instant.now().plusSeconds(3600));

        entityManager.persistAndFlush(token1);
        entityManager.persistAndFlush(token2);
        entityManager.persistAndFlush(token3);

        // Act
        int deletedCount = repository.deleteByUserEmail(testUser.getEmail());
        entityManager.flush();
        entityManager.clear();

        // Assert
        assertThat(deletedCount).isEqualTo(2);
        assertThat(repository.findByTokenRaw("token1")).isEmpty();
        assertThat(repository.findByTokenRaw("token2")).isEmpty();
        assertThat(repository.findByTokenRaw("token3")).isPresent(); // Different user
    }

    /**
     * Should return zero when user has fewer than max tokens.
     */
    @Test
    @DisplayName("Should return zero when deleting oldest tokens and user has fewer than max")
    void shouldReturnZeroWhenUserHasFewerThanMaxTokens() {
        // Arrange - Create only 2 tokens
        String userEmail = testUser.getEmail();

        RefreshToken token1 = new RefreshToken("token1", userEmail, Instant.now().plusSeconds(3600));
        RefreshToken token2 = new RefreshToken("token2", userEmail, Instant.now().plusSeconds(3600));

        entityManager.persistAndFlush(token1);
        entityManager.persistAndFlush(token2);

        // Act - Try to limit to 5 tokens (user only has 2)
        int deletedCount = repository.deleteOldestTokensForUser(userEmail, 5);
        entityManager.flush();
        entityManager.clear();

        // Assert
        assertThat(deletedCount).isEqualTo(0);
        assertThat(repository.findByTokenRaw("token1")).isPresent();
        assertThat(repository.findByTokenRaw("token2")).isPresent();
    }

    /**
     * Should count active tokens for user using helper method.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    @DisplayName("Should count active tokens for user using helper method")
    void shouldCountActiveTokensForUserUsingHelperMethod() throws InterruptedException {
        // Arrange
        String userEmail = testUser.getEmail();

        // Active tokens
        RefreshToken activeToken1 = new RefreshToken("active1", userEmail, Instant.now().plusSeconds(3600));
        RefreshToken activeToken2 = new RefreshToken("active2", userEmail, Instant.now().plusSeconds(3600));

        // Expired token
        RefreshToken expiredToken = new RefreshToken("expired", userEmail, Instant.now().plusSeconds(1));

        // Revoked token
        RefreshToken revokedToken = new RefreshToken("revoked", userEmail, Instant.now().plusSeconds(3600));
        revokedToken.setRevoked(true);

        entityManager.persistAndFlush(activeToken1);
        entityManager.persistAndFlush(activeToken2);
        entityManager.persistAndFlush(expiredToken);
        entityManager.persistAndFlush(revokedToken);

        Thread.sleep(1050); // Wait for expiry

        // Act
        int activeCount = repository.countActiveTokensByUser(userEmail);

        // Assert - Only 2 active tokens should be counted
        assertThat(activeCount).isEqualTo(2);
    }

    /**
     * Should handle concurrent token operations.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    @DisplayName("Should handle concurrent token operations")
    void shouldHandleConcurrentTokenOperations() throws InterruptedException {
        ExecutorService executor = Executors.newFixedThreadPool(5);
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            final int index = i;
            futures.add(executor.submit(() -> {
                RefreshToken token = new RefreshToken(
                        "concurrent-token-" + index,
                        testUser.getEmail().toString(),
                        Instant.now().plusSeconds(3600)
                );
                repository.saveToken(token);
            }));
        }
        // Wait for all futures
        futures.forEach(f -> {
            try {
                f.get();
            } catch (Exception e) { /* handle */ }
        });
        executor.shutdown();
    }

    /**
     * Should handle database constraint violations.
     */
    @Test
    @DisplayName("Should handle database constraint violations")
    void shouldHandleDatabaseConstraintViolations() {
        // Arrange
        String userEmail = testUser.getEmail();
        RefreshToken token1 = new RefreshToken("duplicate-token", userEmail, Instant.now().plusSeconds(3600));
        entityManager.persistAndFlush(token1);

        // Act & Assert - Try to create duplicate token
        RefreshToken token2 = new RefreshToken("duplicate-token", userEmail, Instant.now().plusSeconds(3600));

        assertThatThrownBy(() -> entityManager.persistAndFlush(token2))
                .isInstanceOf(Exception.class); // Should throw constraint violation
    }

    /**
     * Should maintain data integrity during cleanup.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    @DisplayName("Should maintain data integrity during cleanup operations")
    void shouldMaintainDataIntegrityDuringCleanup() throws InterruptedException {
        // Arrange
        String userEmail = testUser.getEmail();

        // Create active tokens
        for (int i = 0; i < 5; i++) {
            RefreshToken token = new RefreshToken("active-" + i, userEmail, Instant.now().plusSeconds(3600));
            entityManager.persistAndFlush(token);
            Thread.sleep(10); // Small delay for creation time difference
        }

        // Create expired tokens
        for (int i = 0; i < 3; i++) {
            RefreshToken token = new RefreshToken("expired-" + i, userEmail, Instant.now().plusSeconds(1));
            entityManager.persistAndFlush(token);
        }

        Thread.sleep(1050); // Wait for expiry

        // Act - Clean up expired tokens first
        int expiredDeleted = repository.deleteExpiredTokens(Instant.now());
        entityManager.flush();
        entityManager.clear();

        // Then clean up oldest active tokens
        int oldestDeleted = repository.deleteOldestTokensForUser(userEmail, 3);
        entityManager.flush();
        entityManager.clear();

        // Assert
        assertThat(expiredDeleted).isEqualTo(3);
        assertThat(oldestDeleted).isEqualTo(2); // 5 - 3 = 2
        assertThat(repository.countActiveTokensByUser(userEmail)).isEqualTo(3);
    }

    /**
     * Should handle null and empty parameters.
     */
    @Test
    @DisplayName("Should handle null and empty parameters gracefully")
    void shouldHandleNullAndEmptyParameters() {
        // Act & Assert - Test with null email
        int nulls = repository.deleteByUserEmail(null);
        assertThat(nulls).isEqualTo(0);

        // Act & Assert - Test with empty email
        int deletedCount = repository.deleteByUserEmail("");
        entityManager.flush();
        entityManager.clear();
        assertThat(deletedCount).isEqualTo(0);

        // Act & Assert - Test counting with null email
        int active = repository.countActiveTokensByUser(null);
        assertThat(active).isEqualTo(0);

    }

    /**
     * Should handle large datasets efficiently.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    @DisplayName("Should handle large datasets efficiently")
    void shouldHandleLargeDatasetsEfficiently() throws InterruptedException {
        // Arrange - Create many tokens
        String userEmail = testUser.getEmail();
        int tokenCount = 100;

        long startTime = System.currentTimeMillis();

        // Create tokens
        for (int i = 0; i < tokenCount; i++) {
            RefreshToken token = new RefreshToken("large-dataset-" + i, userEmail, Instant.now().plusSeconds(3600));
            entityManager.persistAndFlush(token);
        }

        long creationTime = System.currentTimeMillis() - startTime;

        // Act - Bulk operations
        startTime = System.currentTimeMillis();
        int activeCount = repository.countActiveTokensByUser(userEmail);
        long countTime = System.currentTimeMillis() - startTime;

        startTime = System.currentTimeMillis();
        int deletedCount = repository.deleteOldestTokensForUser(userEmail, 10);
        entityManager.flush();
        entityManager.clear();
        long deleteTime = System.currentTimeMillis() - startTime;

        // Assert
        assertThat(activeCount).isEqualTo(tokenCount);
        assertThat(deletedCount).isEqualTo(tokenCount - 10);

        // Performance assertions (these might need adjustment based on your environment)
        assertThat(creationTime).isLessThan(5000); // Should create 100 tokens in < 5 seconds
        assertThat(countTime).isLessThan(1000); // Count should be < 1 second
        assertThat(deleteTime).isLessThan(1000); // Delete should be < 1 second
    }

    /**
     * Should properly handle jpa query methods.
     */
    @Test
    @DisplayName("Should properly handle JPA query methods")
    void shouldProperlyHandleJpaQueryMethods() {
        // Arrange
        String userEmail = testUser.getEmail();

        RefreshToken token1 = new RefreshToken("query-test-1", userEmail, Instant.now().plusSeconds(3600));
        RefreshToken token2 = new RefreshToken("query-test-2", userEmail, Instant.now().plusSeconds(3600));
        RefreshToken token3 = new RefreshToken("query-test-3", secondUser.getEmail(), Instant.now().plusSeconds(3600));

        entityManager.persistAndFlush(token1);
        entityManager.persistAndFlush(token2);
        entityManager.persistAndFlush(token3);

        // Act & Assert - Test findByTokenRaw
        Optional<RefreshToken> found = repository.findByTokenRaw("query-test-1");
        assertThat(found).isPresent();
        assertThat(found.get().getUserEmail()).isEqualTo(userEmail);

        // Act & Assert - Test findValidToken
        Optional<RefreshToken> validToken = repository.findValidToken("query-test-1", Instant.now());
        assertThat(validToken).isPresent();

        // Act & Assert - Test existsByTokenAndRevokedFalseAndExpiryDateAfter (via existsByToken)
        assertThat(repository.existsByToken("query-test-1")).isTrue();
        assertThat(repository.existsByToken("nonexistent")).isFalse();
    }

    /**
     * Helper method to create multiple tokens with different creation times
     */
    private List<RefreshToken> createMultipleTokensWithDelay(String userEmail, int count, String prefix) throws InterruptedException {
        List<RefreshToken> tokens = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            RefreshToken token = new RefreshToken(
                    prefix + "-" + i,
                    userEmail,
                    Instant.now().plusSeconds(3600)
            );
            tokens.add(entityManager.persistAndFlush(token));

            if (i < count - 1) {
                Thread.sleep(10); // Small delay to ensure different creation times
            }
        }

        return tokens;
    }
}