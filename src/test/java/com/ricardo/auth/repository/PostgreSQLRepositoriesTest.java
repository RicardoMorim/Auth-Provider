package com.ricardo.auth.repository;

import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.domain.refreshtoken.RefreshToken;
import com.ricardo.auth.domain.user.Email;
import com.ricardo.auth.domain.user.Password;
import com.ricardo.auth.domain.user.User;
import com.ricardo.auth.domain.user.Username;
import com.ricardo.auth.repository.refreshToken.PostgreSQLRefreshTokenRepository;
import com.ricardo.auth.repository.refreshToken.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for PostgreSQL refresh token repository implementation.
 */
@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "ricardo.auth.repository.type=POSTGRESQL",
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration,org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration"
})
@Transactional
class PostgreSQLRepositoriesTest {

    /**
     * The constant postgres.
     */
    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:18beta3")
            .withDatabaseName("AuthLibraryTest")
            .withUsername("postgres")
            .withPassword("8080");
    @Autowired
    private RefreshTokenRepository repository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private PasswordPolicyService passwordPolicyService;
    @Autowired
    private org.springframework.jdbc.core.JdbcTemplate jdbcTemplate;
    private User testUser;
    private String testUserEmail;

    /**
     * Configure properties.
     *
     * @param registry the registry
     */
    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "none");
        registry.add("spring.jpa.database-platform", () -> "org.hibernate.dialect.PostgreSQLDialect");
    }

    /**
     * Sets up.
     */
    @BeforeEach
    void setUp() {
        // Generate unique user for each test to avoid conflicts
        String uniqueId = UUID.randomUUID().toString().substring(0, 8);
        testUserEmail = "test-" + uniqueId + "@example.com";

        testUser = new User(
                Username.valueOf("testuser-" + uniqueId),
                Email.valueOf(testUserEmail),
                Password.valueOf("TestPassword@123", passwordEncoder, passwordPolicyService)
        );

        // Clean up any existing data for this test
        repository.deleteAll();
        deleteUserByEmail(testUserEmail);
        insertUser(testUser);
    }

    // Helper to insert a user into the users table for FK constraint
    private void insertUser(User user) {
        jdbcTemplate.update(
                "INSERT INTO users (id, username, email, password, version, created_at, updated_at) VALUES (?, ?, ?, ?, 0, NOW(), NOW())",
                UUID.randomUUID(),
                user.getUsername(),
                user.getEmail(),
                user.getPassword()
        );
    }

    // Helper to delete a user by email (cleanup)
    private void deleteUserByEmail(String email) {
        jdbcTemplate.update("DELETE FROM users WHERE email = ?", email);
    }

    /**
     * Should use postgre sql implementation.
     */
    @Test
    void shouldUsePostgreSQLImplementation() {
        assertThat(repository).isInstanceOf(PostgreSQLRefreshTokenRepository.class);
    }

    /**
     * Should create and find token by raw.
     */
    @Test
    void shouldCreateAndFindTokenByRaw() {
        // Arrange
        String tokenValue = "test-token-123";
        RefreshToken token = new RefreshToken(
                tokenValue,
                testUserEmail,
                Instant.now().plusSeconds(3600)
        );

        // Act
        RefreshToken saved = repository.saveToken(token);
        Optional<RefreshToken> found = repository.findByTokenRaw(tokenValue);

        // Assert
        assertThat(saved.getId()).isNotNull();
        assertThat(found).isPresent();
        assertThat(found.get().getToken()).isEqualTo(tokenValue);
        assertThat(found.get().getUserEmail()).isEqualTo(testUserEmail);
    }

    /**
     * Should find valid token only.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    void shouldFindValidTokenOnly() throws InterruptedException {
        // Arrange - Create expired token
        String expiredTokenValue = "expired-token";
        String validTokenValue = "valid-token";

        RefreshToken expiredToken = new RefreshToken(
                expiredTokenValue,
                testUserEmail,
                Instant.now().plusSeconds(1)
        );

        repository.saveToken(expiredToken);
        Thread.sleep(1050); // Ensure expiry time is in the past

        // Arrange - Create valid token
        RefreshToken validToken = new RefreshToken(
                validTokenValue,
                testUserEmail,
                Instant.now().plusSeconds(3600)
        );
        repository.saveToken(validToken);

        // Act
        Optional<RefreshToken> expiredFound = repository.findByToken(expiredTokenValue);
        Optional<RefreshToken> validFound = repository.findByToken(validTokenValue);

        // Assert
        assertThat(expiredFound).isEmpty();
        assertThat(validFound).isPresent();
    }

    /**
     * Should not find revoked tokens with find by token.
     */
    @Test
    void shouldNotFindRevokedTokensWithFindByToken() {
        // Arrange
        String tokenValue = "revoked-token";
        RefreshToken token = new RefreshToken(
                tokenValue,
                testUserEmail,
                Instant.now().plusSeconds(3600)
        );
        token.setRevoked(true);
        repository.saveToken(token);

        // Act
        Optional<RefreshToken> found = repository.findByToken(tokenValue);
        Optional<RefreshToken> foundRaw = repository.findByTokenRaw(tokenValue);

        // Assert
        assertThat(found).isEmpty();
        assertThat(foundRaw).isPresent();
    }

    /**
     * Should revoke all user tokens.
     */
    @Test
    void shouldRevokeAllUserTokens() {
        // Arrange
        String token1Value = "token1";
        String token2Value = "token2";

        RefreshToken token1 = new RefreshToken(token1Value, testUserEmail, Instant.now().plusSeconds(3600));
        RefreshToken token2 = new RefreshToken(token2Value, testUserEmail, Instant.now().plusSeconds(3600));

        repository.saveToken(token1);
        repository.saveToken(token2);

        // Act
        repository.revokeAllUserTokens(testUserEmail);

        // Assert
        Optional<RefreshToken> found1 = repository.findByTokenRaw(token1Value);
        Optional<RefreshToken> found2 = repository.findByTokenRaw(token2Value);

        assertThat(found1).isPresent();
        assertThat(found1.get().isRevoked()).isTrue();
        assertThat(found2).isPresent();
        assertThat(found2.get().isRevoked()).isTrue();
    }

    /**
     * Should delete expired tokens.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    void shouldDeleteExpiredTokens() throws InterruptedException {
        // Arrange
        String expiredTokenValue = "expired-token";
        String validTokenValue = "valid-token";

        RefreshToken expiredToken = new RefreshToken(expiredTokenValue, testUserEmail, Instant.now().plusSeconds(1));
        RefreshToken validToken = new RefreshToken(validTokenValue, testUserEmail, Instant.now().plusSeconds(3600));

        repository.saveToken(expiredToken);
        repository.saveToken(validToken);

        Thread.sleep(1050); // Ensure expiry time is in the past for the expired token

        // Act
        repository.deleteExpiredTokens(Instant.now());

        // Assert
        Optional<RefreshToken> expiredFound = repository.findByTokenRaw(expiredTokenValue);
        Optional<RefreshToken> validFound = repository.findByTokenRaw(validTokenValue);

        assertThat(expiredFound).isEmpty();
        assertThat(validFound).isPresent();
    }

    /**
     * Should count active tokens for user.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    void shouldCountActiveTokensForUser() throws InterruptedException {
        // Arrange
        String activeToken1Value = "active1";
        String activeToken2Value = "active2";
        String expiredTokenValue = "expired";
        String revokedTokenValue = "revoked";

        RefreshToken activeToken1 = new RefreshToken(activeToken1Value, testUserEmail, Instant.now().plusSeconds(3600));
        RefreshToken activeToken2 = new RefreshToken(activeToken2Value, testUserEmail, Instant.now().plusSeconds(3600));
        RefreshToken expiredToken = new RefreshToken(expiredTokenValue, testUserEmail, Instant.now().plusSeconds(1));
        RefreshToken revokedToken = new RefreshToken(revokedTokenValue, testUserEmail, Instant.now().plusSeconds(3600));
        revokedToken.setRevoked(true);

        repository.saveToken(activeToken1);
        repository.saveToken(activeToken2);
        repository.saveToken(expiredToken);
        repository.saveToken(revokedToken);

        Thread.sleep(1050); // Ensure expiry time is in the past for the expired token

        // Act
        long count = repository.countByUserEmailAndRevokedFalseAndExpiryDateAfter(testUserEmail, Instant.now());

        // Assert
        assertThat(count).isEqualTo(2);
    }

    /**
     * Should update existing token.
     */
    @Test
    void shouldUpdateExistingToken() {
        // Arrange
        String tokenValue = "update-token";
        RefreshToken token = new RefreshToken(tokenValue, testUserEmail, Instant.now().plusSeconds(3600));
        RefreshToken saved = repository.saveToken(token);

        // Act - Update token
        saved.setRevoked(true);
        RefreshToken updated = repository.saveToken(saved);

        // Assert
        assertThat(updated.getId()).isEqualTo(saved.getId());
        assertThat(updated.isRevoked()).isTrue();

        Optional<RefreshToken> found = repository.findByTokenRaw(tokenValue);
        assertThat(found).isPresent();
        assertThat(found.get().isRevoked()).isTrue();
    }

    /**
     * Should delete token by value.
     */
    @Test
    void shouldDeleteTokenByValue() {
        // Arrange
        String tokenValue = "delete-token";
        RefreshToken token = new RefreshToken(tokenValue, testUserEmail, Instant.now().plusSeconds(3600));
        repository.saveToken(token);

        // Act
        repository.deleteByToken(tokenValue);

        // Assert
        Optional<RefreshToken> found = repository.findByTokenRaw(tokenValue);
        assertThat(found).isEmpty();
    }

    /**
     * Should check token existence.
     */
    @Test
    void shouldCheckTokenExistence() {
        // Arrange
        String tokenValue = "exists-token";
        RefreshToken token = new RefreshToken(tokenValue, testUserEmail, Instant.now().plusSeconds(3600));
        repository.saveToken(token);

        // Act & Assert
        assertThat(repository.existsByToken(tokenValue)).isTrue();
        assertThat(repository.existsByToken("nonexistent-token")).isFalse();
    }

    /**
     * Should delete oldest tokens when user exceeds limit.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    @DisplayName("Should delete oldest tokens when user exceeds max token limit")
    void shouldDeleteOldestTokensWhenUserExceedsLimit() throws InterruptedException {
        // Arrange - Create 5 tokens with different creation times
        RefreshToken token1 = new RefreshToken("token1", testUserEmail, Instant.now().plusSeconds(3600));
        RefreshToken token2 = new RefreshToken("token2", testUserEmail, Instant.now().plusSeconds(3600));
        RefreshToken token3 = new RefreshToken("token3", testUserEmail, Instant.now().plusSeconds(3600));
        RefreshToken token4 = new RefreshToken("token4", testUserEmail, Instant.now().plusSeconds(3600));
        RefreshToken token5 = new RefreshToken("token5", testUserEmail, Instant.now().plusSeconds(3600));

        // Save tokens with small delays to ensure different creation times
        repository.saveToken(token1);
        Thread.sleep(10);
        repository.saveToken(token2);
        Thread.sleep(10);
        repository.saveToken(token3);
        Thread.sleep(10);
        repository.saveToken(token4);
        Thread.sleep(10);
        repository.saveToken(token5);

        // Act - Keep only 3 tokens (should delete 2 oldest)
        int deletedCount = repository.deleteOldestTokensForUser(testUserEmail, 3);

        // Assert
        assertThat(deletedCount).isEqualTo(2);

        // Verify the oldest tokens were deleted
        assertThat(repository.findByTokenRaw("token1")).isEmpty();
        assertThat(repository.findByTokenRaw("token2")).isEmpty();

        // Verify the newest tokens still exist
        assertThat(repository.findByTokenRaw("token3")).isPresent();
        assertThat(repository.findByTokenRaw("token4")).isPresent();
        assertThat(repository.findByTokenRaw("token5")).isPresent();
    }

    /**
     * Should return zero when user has fewer than max tokens.
     */
    @Test
    @DisplayName("Should return zero when deleting oldest tokens and user has fewer than max")
    void shouldReturnZeroWhenUserHasFewerThanMaxTokens() {
        // Arrange - Create only 2 tokens
        RefreshToken token1 = new RefreshToken("token1", testUserEmail, Instant.now().plusSeconds(3600));
        RefreshToken token2 = new RefreshToken("token2", testUserEmail, Instant.now().plusSeconds(3600));

        repository.saveToken(token1);
        repository.saveToken(token2);

        // Act - Try to limit to 5 tokens (user only has 2)
        int deletedCount = repository.deleteOldestTokensForUser(testUserEmail, 5);

        // Assert
        assertThat(deletedCount).isEqualTo(0);

        // Verify both tokens still exist
        assertThat(repository.findByTokenRaw("token1")).isPresent();
        assertThat(repository.findByTokenRaw("token2")).isPresent();
    }

    /**
     * Should return zero when user has no tokens.
     */
    @Test
    @DisplayName("Should return zero when deleting oldest tokens for user with no tokens")
    void shouldReturnZeroWhenUserHasNoTokens() {
        // Arrange - User has no tokens
        String userEmail = "nonexistent@example.com";

        // Act
        int deletedCount = repository.deleteOldestTokensForUser(userEmail, 3);

        // Assert
        assertThat(deletedCount).isEqualTo(0);
    }

    /**
     * Should delete all tokens for user.
     */
    @Test
    @DisplayName("Should delete all tokens for a specific user")
    void shouldDeleteAllTokensForUser() {
        // Arrange - Create tokens for multiple users
        String userEmail2 = "other@example.com";
        // Insert user2 into users table for FK constraint
        deleteUserByEmail(userEmail2);
        insertUser(new User(
                Username.valueOf("otheruser"),
                Email.valueOf(userEmail2),
                Password.valueOf("OtherPassword@123", passwordEncoder, passwordPolicyService)
        ));

        RefreshToken token1 = new RefreshToken("token1", testUserEmail, Instant.now().plusSeconds(3600));
        RefreshToken token2 = new RefreshToken("token2", testUserEmail, Instant.now().plusSeconds(3600));
        RefreshToken token3 = new RefreshToken("token3", userEmail2, Instant.now().plusSeconds(3600));

        repository.saveToken(token1);
        repository.saveToken(token2);
        repository.saveToken(token3);

        // Act - Delete all tokens for user1
        int deletedCount = repository.deleteByUserEmail(testUserEmail);

        // Assert
        assertThat(deletedCount).isEqualTo(2);

        // Verify user1's tokens are deleted
        assertThat(repository.findByTokenRaw("token1")).isEmpty();
        assertThat(repository.findByTokenRaw("token2")).isEmpty();

        // Verify user2's token still exists
        assertThat(repository.findByTokenRaw("token3")).isPresent();
    }

    /**
     * Should count active tokens for users.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    @DisplayName("Should count active tokens for user correctly")
    void shouldCountActiveTokensForUsers() throws InterruptedException {
        // Arrange - Create various types of tokens
        String otherUserEmail = "other@example.com";
        // Insert other user for FK constraint
        deleteUserByEmail(otherUserEmail);
        insertUser(new User(
                Username.valueOf("otheruser"),
                Email.valueOf(otherUserEmail),
                Password.valueOf("OtherPassword@123", passwordEncoder, passwordPolicyService)
        ));

        // Active tokens for test user
        RefreshToken activeToken1 = new RefreshToken("active1", testUserEmail, Instant.now().plusSeconds(3600));
        RefreshToken activeToken2 = new RefreshToken("active2", testUserEmail, Instant.now().plusSeconds(3600));

        // Expired token for test user
        RefreshToken expiredToken = new RefreshToken("expired", testUserEmail, Instant.now().plusSeconds(1));

        // Revoked token for test user
        RefreshToken revokedToken = new RefreshToken("revoked", testUserEmail, Instant.now().plusSeconds(3600));
        revokedToken.setRevoked(true);

        // Token for different user (should not be counted)
        RefreshToken otherUserToken = new RefreshToken("other", otherUserEmail, Instant.now().plusSeconds(3600));

        repository.saveToken(activeToken1);
        repository.saveToken(activeToken2);
        repository.saveToken(expiredToken);
        repository.saveToken(revokedToken);
        repository.saveToken(otherUserToken);

        // Wait for expiry
        Thread.sleep(1050);

        // Act - Count active tokens for test user only
        int activeCount = repository.countActiveTokensByUser(testUserEmail);

        // Assert - Only 2 active tokens should be counted for test user
        assertThat(activeCount).isEqualTo(2);
    }

    /**
     * Should return zero when counting active tokens for user with no tokens.
     */
    @Test
    @DisplayName("Should return zero when counting active tokens for user with no tokens")
    void shouldReturnZeroWhenCountingActiveTokensForUserWithNoTokens() {
        // Arrange - User has no tokens
        String userEmail = "nonexistent@example.com";

        // Act
        int activeCount = repository.countActiveTokensByUser(userEmail);

        // Assert
        assertThat(activeCount).isEqualTo(0);
    }

    /**
     * Should handle concurrent token creation and cleanup.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    @DisplayName("Should handle concurrent token creation and cleanup")
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void shouldHandleConcurrentTokenCreationAndCleanup() throws InterruptedException {
        // Arrange - Ensure user exists for FK constraint, and synchronize thread start
        deleteUserByEmail(testUserEmail);
        insertUser(testUser); // Insert and commit user before threads start

        int threadCount = 7;
        CountDownLatch latch = new CountDownLatch(threadCount);
        java.util.concurrent.CyclicBarrier barrier = new java.util.concurrent.CyclicBarrier(threadCount);

        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < threadCount; i++) {
            final int tokenIndex = i;
            Thread t = new Thread(() -> {
                try {
                    barrier.await(); // Ensure all threads start at the same time
                    RefreshToken token = new RefreshToken(
                            "concurrent-token-" + tokenIndex,
                            testUserEmail,
                            Instant.now().plusSeconds(3600)
                    );
                    repository.saveToken(token);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                } finally {
                    latch.countDown();
                }
            });
            threads.add(t);
            t.start();
        }

        latch.await(); // Wait for all threads to complete

        // Act - Delete oldest tokens to keep only 5
        int deletedCount = repository.deleteOldestTokensForUser(testUserEmail, 5);

        // Assert
        assertThat(deletedCount).isEqualTo(2); // Should delete 2 tokens (7 - 5)
        assertThat(repository.countActiveTokensByUser(testUserEmail)).isEqualTo(5);
    }

    /**
     * Should handle postgre sql timestamp operations.
     */
    @Test
    @DisplayName("Should properly handle PostgreSQL-specific timestamp operations")
    void shouldHandlePostgreSQLTimestampOperations() {
        // Arrange - Create token with specific timestamp (rounded to microseconds for PostgreSQL)
        Instant specificTime = Instant.now().plusSeconds(1000).truncatedTo(ChronoUnit.MICROS);

        RefreshToken token = new RefreshToken("timestamp-token", testUserEmail, specificTime);
        RefreshToken savedToken = repository.saveToken(token);

        // Act - Retrieve and verify timestamp handling
        Optional<RefreshToken> retrievedToken = repository.findByTokenRaw("timestamp-token");

        // Assert
        assertThat(retrievedToken).isPresent();
        // PostgreSQL stores timestamps with microsecond precision, so we need to truncate for comparison
        assertThat(retrievedToken.get().getExpiryDate().truncatedTo(ChronoUnit.MICROS))
                .isEqualTo(specificTime);
        assertThat(retrievedToken.get().getCreatedAt()).isNotNull();
        assertThat(retrievedToken.get().getCreatedAt()).isBeforeOrEqualTo(Instant.now());
    }

    /**
     * Should handle large token values.
     */
    @Test
    @DisplayName("Should handle large token values correctly")
    void shouldHandleLargeTokenValues() {
        // Arrange - Create token with large value
        String largeTokenValue = "a".repeat(750); // 750 character token

        RefreshToken token = new RefreshToken(largeTokenValue, testUserEmail, Instant.now().plusSeconds(3600));

        // Act
        RefreshToken savedToken = repository.saveToken(token);
        Optional<RefreshToken> retrievedToken = repository.findByTokenRaw(largeTokenValue);

        // Assert
        assertThat(savedToken.getToken()).isEqualTo(largeTokenValue);
        assertThat(retrievedToken).isPresent();
        assertThat(retrievedToken.get().getToken()).isEqualTo(largeTokenValue);
    }

    /**
     * Should handle database constraint violations.
     */
    @Test
    @DisplayName("Should handle database constraint violations gracefully")
    void shouldHandleDatabaseConstraintViolations() {
        // Arrange - Create token
        RefreshToken token1 = new RefreshToken("duplicate-token", testUserEmail, Instant.now().plusSeconds(3600));
        repository.saveToken(token1);

        // Act & Assert - Try to create duplicate token
        RefreshToken token2 = new RefreshToken("duplicate-token", testUserEmail, Instant.now().plusSeconds(3600));

        assertThatThrownBy(() -> repository.saveToken(token2))
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
        // Arrange - Create tokens with mixed states
        // Create active tokens
        for (int i = 0; i < 5; i++) {
            RefreshToken token = new RefreshToken("active-" + i, testUserEmail, Instant.now().plusSeconds(3600));
            repository.saveToken(token);
            Thread.sleep(10); // Small delay for creation time difference
        }

        // Create expired tokens
        for (int i = 0; i < 3; i++) {
            RefreshToken token = new RefreshToken("expired-" + i, testUserEmail, Instant.now().plusSeconds(1));
            repository.saveToken(token);
        }

        Thread.sleep(1050); // Wait for expiry

        // Act - Clean up expired tokens
        int expiredDeleted = repository.deleteExpiredTokens(Instant.now());

        // Then clean up oldest active tokens
        int oldestDeleted = repository.deleteOldestTokensForUser(testUserEmail, 3);

        // Assert
        assertThat(expiredDeleted).isEqualTo(3);
        assertThat(oldestDeleted).isEqualTo(2); // 5 - 3 = 2
        assertThat(repository.countActiveTokensByUser(testUserEmail)).isEqualTo(3);
    }

    /**
     * Should handle null and empty parameters.
     */
    @Test
    @DisplayName("Should handle null and empty parameters gracefully")
    void shouldHandleNullAndEmptyParameters() {
        // Act & Assert - Test with null email
        int deleted = repository.deleteByUserEmail(null);
        assertThat(deleted).isEqualTo(0);

        // Act & Assert - Test with empty email
        int deletedCount = repository.deleteByUserEmail("");
        assertThat(deletedCount).isEqualTo(0);

        // Act & Assert - Test counting with null email
        int count = repository.countActiveTokensByUser(null);
        assertThat(count).isEqualTo(0);
    }

    /**
     * Should verify created at field handling.
     */
    @Test
    @DisplayName("Should verify createdAt field is properly set and retrieved")
    void shouldVerifyCreatedAtFieldHandling() {
        // Arrange
        RefreshToken token = new RefreshToken("created-at-test", testUserEmail, Instant.now().plusSeconds(3600));

        // Act
        RefreshToken savedToken = repository.saveToken(token);
        Optional<RefreshToken> retrievedToken = repository.findByTokenRaw("created-at-test");

        // Assert
        assertThat(retrievedToken).isPresent();
        assertThat(retrievedToken.get().getCreatedAt()).isNotNull();

        assertThat(retrievedToken.get().getCreatedAt().truncatedTo(ChronoUnit.MILLIS))
                .isEqualTo(savedToken.getCreatedAt().truncatedTo(ChronoUnit.MILLIS));
    }


}

