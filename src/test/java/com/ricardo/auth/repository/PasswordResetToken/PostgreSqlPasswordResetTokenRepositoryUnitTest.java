package com.ricardo.auth.repository.PasswordResetToken;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.domain.passwordresettoken.PasswordResetToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;

import javax.sql.DataSource;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class PostgreSqlPasswordResetTokenRepositoryUnitTest {

    private JdbcTemplate jdbcTemplate;
    private PostgreSqlPasswordResetTokenRepository repository;

    @BeforeEach
    void setUp() {
        jdbcTemplate = mock(JdbcTemplate.class);

        AuthProperties properties = new AuthProperties();
        properties.getRepository().getDatabase().setPasswordResetTokensTable("password_reset_tokens");

        repository = new PostgreSqlPasswordResetTokenRepository(mock(DataSource.class), properties);
        ReflectionTestUtils.setField(repository, "jdbcTemplate", jdbcTemplate);
    }

    @Test
    void constructor_WithBlankTableName_ShouldThrow() {
        AuthProperties properties = new AuthProperties();
        properties.getRepository().getDatabase().setPasswordResetTokensTable("   ");

        assertThatThrownBy(() -> new PostgreSqlPasswordResetTokenRepository(mock(DataSource.class), properties))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cannot be null or blank");
    }

    @Test
    void findByTokenAndNotUsed_WhenNoRow_ShouldReturnEmpty() {
        when(jdbcTemplate.queryForObject(anyString(), any(org.springframework.jdbc.core.RowMapper.class), eq("missing")))
                .thenThrow(new EmptyResultDataAccessException(1));

        Optional<PasswordResetToken> result = repository.findByTokenAndNotUsed("missing");

        assertThat(result).isEmpty();
    }

    @Test
    void saveToken_WhenNewToken_ShouldInsertAndSetId() {
        PasswordResetToken token = new PasswordResetToken("token-value", "user@example.com", Instant.now().plusSeconds(3600));
        UUID generatedId = UUID.randomUUID();

        when(jdbcTemplate.queryForObject(
                anyString(),
                eq(UUID.class),
                any(), any(), any(), any(), any(), any()
        )).thenReturn(generatedId);

        PasswordResetToken saved = repository.saveToken(token);

        assertThat(saved.getId()).isEqualTo(generatedId);
    }

    @Test
    void saveToken_WhenExistingToken_ShouldUpdate() {
        PasswordResetToken token = new PasswordResetToken("token-value", "user@example.com", Instant.now().plusSeconds(3600));
        token.setId(UUID.randomUUID());
        token.setUsed(true);
        token.setUsedAt(Instant.now());

        PasswordResetToken updated = repository.saveToken(token);

        assertThat(updated.getId()).isEqualTo(token.getId());
        verify(jdbcTemplate).update(anyString(), any(), any(), any());
    }

    @Test
    void countResetAttemptsForEmailSince_ShouldReturnCount() {
        when(jdbcTemplate.queryForObject(anyString(), eq(Integer.class), any(), any())).thenReturn(3);

        int count = repository.countResetAttemptsForEmailSince("user@example.com", Instant.now().minusSeconds(3600));

        assertThat(count).isEqualTo(3);
    }

    @Test
    void existsByTokenAndNotUsed_ShouldUseFindMethod() {
        PasswordResetToken token = new PasswordResetToken("token-value", "user@example.com", Instant.now().plusSeconds(3600));
        when(jdbcTemplate.queryForObject(anyString(), any(org.springframework.jdbc.core.RowMapper.class), eq("token-value")))
                .thenReturn(token);

        assertThat(repository.existsByTokenAndNotUsed("token-value")).isTrue();
    }

    @Test
    void markTokenAsUsed_AndDeleteExpiredTokens_ShouldExecuteUpdates() {
        repository.markTokenAsUsed("token-value", Instant.now());
        repository.deleteExpiredTokens(Instant.now());
        repository.invalidateTokensForUser("user@example.com", Instant.now());

        verify(jdbcTemplate).update(contains("SET used = true, used_at = ? WHERE token = ?"), any(), eq("token-value"));
        verify(jdbcTemplate).update(contains("DELETE FROM password_reset_tokens WHERE expiry_date < ? OR used = true"), any(java.sql.Timestamp.class));
        verify(jdbcTemplate).update(contains("SET used = true, used_at = ? WHERE email = ? AND used = false"), any(), eq("user@example.com"));
    }
}
