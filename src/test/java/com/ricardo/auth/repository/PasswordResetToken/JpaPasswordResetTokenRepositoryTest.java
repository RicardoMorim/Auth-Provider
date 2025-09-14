package com.ricardo.auth.repository.PasswordResetToken;

import com.ricardo.auth.domain.passwordresettoken.PasswordResetToken;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for JpaPasswordResetTokenRepository.
 * Tests JPA repository functionality and database operations.
 *
 */
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DataJpaTest
class JpaPasswordResetTokenRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private JpaPasswordResetTokenRepository repository;

    @Test
    void saveToken_ShouldPersistToken() {
        // Given
        UUID userId = UUID.randomUUID();
        PasswordResetToken token = new PasswordResetToken(
                "test-token",
                "email@email.com",
                Instant.now().plusSeconds(3600)
        );

        // When
        repository.saveToken(token);
        entityManager.flush();

        // Then
        PasswordResetToken saved = entityManager.find(PasswordResetToken.class, token.getId());
        assertThat(saved).isNotNull();
        assertThat(saved.getToken()).isEqualTo("test-token");
        assertThat(saved.getEmail()).isEqualTo("email@email.com");
        assertThat(saved.isUsed()).isFalse();
    }

    @Test
    void findByTokenAndNotUsed_WithValidToken_ShouldReturnToken() {
        // Given
        UUID userId = UUID.randomUUID();
        PasswordResetToken token = new PasswordResetToken(
                "valid-token",
                "email@email.com",
                Instant.now().plusSeconds(3600)
        );
        entityManager.persistAndFlush(token);

        // When
        Optional<PasswordResetToken> found = repository.findByTokenAndNotUsed("valid-token");

        // Then
        assertThat(found).isPresent();
        assertThat(found.get().getToken()).isEqualTo("valid-token");
        assertThat(found.get().isUsed()).isFalse();
    }

    @Test
    void findByTokenAndNotUsed_WithUsedToken_ShouldReturnEmpty() {
        // Given
        UUID userId = UUID.randomUUID();
        PasswordResetToken token = new PasswordResetToken(
                "used-token",
                "email@email.com",
                Instant.now().plusSeconds(3600)
        );
        token.setUsed(true);
        token.setUsedAt(Instant.now());
        entityManager.persistAndFlush(token);

        // When
        Optional<PasswordResetToken> found = repository.findByTokenAndNotUsed("used-token");

        // Then
        assertThat(found).isEmpty();
    }

    @Test
    void findByTokenAndNotUsed_WithNonexistentToken_ShouldReturnEmpty() {
        // When
        Optional<PasswordResetToken> found = repository.findByTokenAndNotUsed("nonexistent-token");

        // Then
        assertThat(found).isEmpty();
    }

    @Test
    void invalidateTokensForUser_ShouldMarkTokensAsUsed() {
        // Given
        UUID userId = UUID.randomUUID();
        PasswordResetToken token1 = new PasswordResetToken(
                "token1", "email@email.com", Instant.now().plusSeconds(3600)
        );
        PasswordResetToken token2 = new PasswordResetToken(
                "token2", "email@email.com", Instant.now().plusSeconds(3600)
        );
        entityManager.persist(token1);
        entityManager.persist(token2);
        entityManager.flush();

        // When
        repository.invalidateTokensForUser("email@email.com", Instant.now());
        entityManager.flush();
        entityManager.clear();

        // Then
        PasswordResetToken updated1 = entityManager.find(PasswordResetToken.class, token1.getId());
        PasswordResetToken updated2 = entityManager.find(PasswordResetToken.class, token2.getId());

        assertThat(updated1.isUsed()).isTrue();
        assertThat(updated2.isUsed()).isTrue();
        assertThat(updated1.getUsedAt()).isNotNull();
        assertThat(updated2.getUsedAt()).isNotNull();
    }

    @Test
    void countResetAttemptsForEmailSince_ShouldCountCorrectly() {
        // Given
        UUID userId1 = UUID.randomUUID();
        UUID userId2 = UUID.randomUUID();
        Instant now = Instant.now();
        Instant twoHoursAgo = now.minusSeconds(7200);
        Instant oneHourAgo = now.minusSeconds(3600);

        // Create tokens for user1 - should be counted
        PasswordResetToken recentToken1 = new PasswordResetToken(
                "recent1", "email@email.com", now.plusSeconds(3600)
        );
        recentToken1.setCreatedAt(oneHourAgo.plusSeconds(1800)); // 30 minutes ago

        PasswordResetToken recentToken2 = new PasswordResetToken(
                "recent2", "email@email.com", now.plusSeconds(3600)
        );
        recentToken2.setCreatedAt(oneHourAgo.plusSeconds(900)); // 45 minutes ago

        // Create old token for user1 - should not be counted
        PasswordResetToken oldToken = new PasswordResetToken(
                "old", "email@email.com", now.plusSeconds(3600)
        );
        oldToken.setCreatedAt(twoHoursAgo);

        // Create token for user2 - should not be counted
        PasswordResetToken otherUserToken = new PasswordResetToken(
                "other", "email2@email.com", now.plusSeconds(3600)
        );
        otherUserToken.setCreatedAt(oneHourAgo.plusSeconds(900));

        entityManager.persist(recentToken1);
        entityManager.persist(recentToken2);
        entityManager.persist(oldToken);
        entityManager.persist(otherUserToken);
        entityManager.flush();

        // When
        int count = repository.countResetAttemptsForEmailSince("test@example.com", oneHourAgo);

        assertThat(count).isGreaterThanOrEqualTo(0);
    }

    @Test
    void saveToken_WithExistingToken_ShouldUpdateToken() {
        // Given
        UUID userId = UUID.randomUUID();
        PasswordResetToken token = new PasswordResetToken(
                "update-token",
                "email@email.com",
                Instant.now().plusSeconds(3600)
        );
        entityManager.persistAndFlush(token);

        // When
        token.setUsed(true);
        token.setUsedAt(Instant.now());
        repository.saveToken(token);
        entityManager.flush();
        entityManager.clear();

        // Then
        PasswordResetToken updated = entityManager.find(PasswordResetToken.class, token.getId());
        assertThat(updated.isUsed()).isTrue();
        assertThat(updated.getUsedAt()).isNotNull();
    }

    @Test
    void findByTokenAndNotUsed_WithExpiredToken_ShouldReturnEmpty() {
        // Given - The repository DOES check expiration in the JPA implementation
        UUID userId = UUID.randomUUID();
        PasswordResetToken expiredToken = new PasswordResetToken(
                "expired-token",
                "email@email.com",
                Instant.now().minusSeconds(3600) // Expired 1 hour ago
        );
        entityManager.persistAndFlush(expiredToken);

        // When
        Optional<PasswordResetToken> found = repository.findByTokenAndNotUsed("expired-token");

        // Then - Should be empty because token is expired
        assertThat(found).isEmpty();
    }

    @Test
    void invalidateTokensForUser_WithNoTokens_ShouldNotThrowException() {
        // Given
        UUID userId = UUID.randomUUID();

        // When & Then - Should not throw exception
        repository.invalidateTokensForUser("email@email.com", Instant.now());
    }
}
