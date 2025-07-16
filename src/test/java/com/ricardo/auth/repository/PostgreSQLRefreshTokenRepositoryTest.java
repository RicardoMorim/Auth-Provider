package com.ricardo.auth.repository;

import com.ricardo.auth.domain.tokenResponse.RefreshToken;
import com.ricardo.auth.domain.user.Email;
import com.ricardo.auth.domain.user.Password;
import com.ricardo.auth.domain.user.User;
import com.ricardo.auth.domain.user.Username;
import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.repository.refreshToken.PostgreSQLRefreshTokenRepository;
import com.ricardo.auth.repository.refreshToken.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for PostgreSQL refresh token repository implementation.
 */
@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "ricardo.auth.refresh-tokens.repository.type=postgresql"
})
@Transactional
class PostgreSQLRefreshTokenRepositoryTest {
    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17")
            .withDatabaseName("AuthLibraryTest")
            .withUsername("postgres")
            .withPassword("8080");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
        registry.add("spring.jpa.database-platform", () -> "org.hibernate.dialect.PostgreSQLDialect");
    }

    @Autowired
    private RefreshTokenRepository repository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private PasswordPolicyService passwordPolicyService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = new User(
                Username.valueOf("testuser"),
                Email.valueOf("test@example.com"),
                Password.valueOf("TestPassword@123", passwordEncoder, passwordPolicyService)
        );
    }

    @Test
    void shouldUsePostgreSQLImplementation() {
        assertThat(repository).isInstanceOf(PostgreSQLRefreshTokenRepository.class);
    }

    @Test
    void shouldCreateAndFindTokenByRaw() {
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
        assertThat(found).isPresent();
        assertThat(found.get().getToken()).isEqualTo("test-token-123");
        assertThat(found.get().getUserEmail()).isEqualTo(testUser.getEmail());
    }

    @Test
    void shouldFindValidTokenOnly() throws InterruptedException {
        // Arrange - Create expired token
        RefreshToken expiredToken = new RefreshToken(
                "expired-token",
                testUser.getEmail(),
                Instant.now().plusSeconds(1)
        );

        repository.save(expiredToken);
        Thread.sleep(1050); // Ensure expiry time is in the past

        // Arrange - Create valid token
        RefreshToken validToken = new RefreshToken(
                "valid-token",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        repository.save(validToken);

        // Act
        Optional<RefreshToken> expiredFound = repository.findByToken("expired-token");
        Optional<RefreshToken> validFound = repository.findByToken("valid-token");

        // Assert
        assertThat(expiredFound).isEmpty();
        assertThat(validFound).isPresent();
    }

    @Test
    void shouldNotFindRevokedTokensWithFindByToken() {
        // Arrange
        RefreshToken token = new RefreshToken(
                "revoked-token",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        token.setRevoked(true);
        repository.save(token);

        // Act
        Optional<RefreshToken> found = repository.findByToken("revoked-token");
        Optional<RefreshToken> foundRaw = repository.findByTokenRaw("revoked-token");

        // Assert
        assertThat(found).isEmpty();
        assertThat(foundRaw).isPresent();
    }

    @Test
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
        repository.save(token1);
        repository.save(token2);

        // Act
        repository.revokeAllUserTokens(testUser.getEmail());

        // Assert
        Optional<RefreshToken> found1 = repository.findByTokenRaw("token1");
        Optional<RefreshToken> found2 = repository.findByTokenRaw("token2");

        assertThat(found1).isPresent();
        assertThat(found1.get().isRevoked()).isTrue();
        assertThat(found2).isPresent();
        assertThat(found2.get().isRevoked()).isTrue();
    }

    @Test
    void shouldDeleteExpiredTokens() throws InterruptedException {
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
        repository.save(expiredToken);
        repository.save(validToken);

        Thread.sleep(1050); // Ensure expiry time is in the past for the expired token

        // Act
        repository.deleteExpiredTokens(Instant.now());

        // Assert
        Optional<RefreshToken> expiredFound = repository.findByTokenRaw("expired-token");
        Optional<RefreshToken> validFound = repository.findByTokenRaw("valid-token");

        assertThat(expiredFound).isEmpty();
        assertThat(validFound).isPresent();
    }

    @Test
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

        repository.save(activeToken1);
        repository.save(activeToken2);
        repository.save(expiredToken);
        repository.save(revokedToken);

        Thread.sleep(1050); // Ensure expiry time is in the past for the expired token

        // Act
        long count = repository.countByUserEmailAndRevokedFalseAndExpiryDateAfter(
                testUser.getEmail(),
                Instant.now()
        );

        // Assert
        assertThat(count).isEqualTo(2);
    }

    @Test
    void shouldUpdateExistingToken() {
        // Arrange
        RefreshToken token = new RefreshToken(
                "update-token",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        RefreshToken saved = repository.save(token);

        // Act - Update token
        saved.setRevoked(true);
        RefreshToken updated = repository.save(saved);

        // Assert
        assertThat(updated.getId()).isEqualTo(saved.getId());
        assertThat(updated.isRevoked()).isTrue();

        Optional<RefreshToken> found = repository.findByTokenRaw("update-token");
        assertThat(found).isPresent();
        assertThat(found.get().isRevoked()).isTrue();
    }

    @Test
    void shouldDeleteTokenByValue() {
        // Arrange
        RefreshToken token = new RefreshToken(
                "delete-token",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        repository.save(token);

        // Act
        repository.deleteByToken("delete-token");

        // Assert
        Optional<RefreshToken> found = repository.findByTokenRaw("delete-token");
        assertThat(found).isEmpty();
    }

    @Test
    void shouldCheckTokenExistence() {
        // Arrange
        RefreshToken token = new RefreshToken(
                "exists-token",
                testUser.getEmail(),
                Instant.now().plusSeconds(3600)
        );
        repository.save(token);

        // Act & Assert
        assertThat(repository.existsByToken("exists-token")).isTrue();
        assertThat(repository.existsByToken("nonexistent-token")).isFalse();
    }
}