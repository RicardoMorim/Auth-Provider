package com.ricardo.auth.repository.PasswordResetToken;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.domain.passwordresettoken.PasswordResetToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public class PostgreSqlPasswordResetTokenRepository implements PasswordResetTokenRepository {

    private static final Logger logger = LoggerFactory.getLogger(PostgreSqlPasswordResetTokenRepository.class);
    private final JdbcTemplate jdbcTemplate;
    private final AuthProperties authProperties;
    private final PasswordResetTokenRowMapper rowMapper = new PasswordResetTokenRowMapper();

    public PostgreSqlPasswordResetTokenRepository(DataSource dataSource, AuthProperties authProperties) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
        this.authProperties = authProperties;
    }

    @Override
    public Optional<PasswordResetToken> findByTokenAndNotUsed(String token) {
        String sql = "SELECT * FROM " + getTableName() + " WHERE token = ? AND used = false AND expiry_date > NOW()";
        try {
            PasswordResetToken result = jdbcTemplate.queryForObject(sql, rowMapper, token);
            return Optional.ofNullable(result);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    @Override
    public void invalidateTokensForUser(UUID userId, Instant now) {
        String sql = "UPDATE " + getTableName() + " SET used = true, usedAt = ? WHERE user_id = ? AND used = false";
        jdbcTemplate.update(sql, now, userId);
    }

    @Override
    public int countResetAttemptsForEmailSince(String email, Instant since) {
        String sql = """
            SELECT COUNT(*) FROM %s prt 
            JOIN users u ON prt.user_id = u.id 
            WHERE u.email = ? AND prt.created_at > ?
            """.formatted(getTableName());
        return jdbcTemplate.queryForObject(sql, Integer.class, email, Timestamp.from(since));
    }

    @Override
    public int countResetAttemptsForIpSince(String ipAddress, Instant since) {
        // This would require storing IP addresses - for now return 0
        // In production, you'd want to create an additional table for tracking IP-based attempts
        return 0;
    }

    @Override
    public PasswordResetToken saveToken(PasswordResetToken token) {
        if (token.getId() == null) {
            return insertToken(token);
        } else {
            return updateToken(token);
        }
    }

    private PasswordResetToken insertToken(PasswordResetToken token) {
        String sql = """
            INSERT INTO %s (id, token, user_id, expiry_date, used, used_at, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id
            """.formatted(getTableName());
        
        UUID id = UUID.randomUUID();
        token.setId(id);
        
        jdbcTemplate.update(sql, 
            id,
            token.getToken(),
            token.getUserId(),
            Timestamp.from(token.getExpiryDate()),
            token.isUsed(),
            token.getUsedAt() != null ? Timestamp.from(token.getUsedAt()) : null,
            Timestamp.from(token.getCreatedAt())
        );
        
        return token;
    }

    private PasswordResetToken updateToken(PasswordResetToken token) {
        String sql = """
            UPDATE %s SET used = ?, used_at = ? 
            WHERE id = ?
            """.formatted(getTableName());
        
        jdbcTemplate.update(sql, 
            token.isUsed(),
            token.getUsedAt() != null ? Timestamp.from(token.getUsedAt()) : null,
            token.getId()
        );
        
        return token;
    }

    @Override
    public void deleteExpiredTokens(Instant before) {
        String sql = "DELETE FROM " + getTableName() + " WHERE expiry_date < ? OR used = true";
        jdbcTemplate.update(sql, Timestamp.from(before));
    }

    @Override
    public boolean existsByTokenAndNotUsed(String token) {
        return findByTokenAndNotUsed(token).isPresent();
    }

    @Override
    public void markTokenAsUsed(String token, Instant usedAt) {
        String sql = "UPDATE " + getTableName() + " SET used = true, used_at = ? WHERE token = ?";
        jdbcTemplate.update(sql, Timestamp.from(usedAt), token);
    }

    private String getTableName() {
        return authProperties.getRepository().getDatabase().getPasswordResetTokensTable();
    }

    private static class PasswordResetTokenRowMapper implements RowMapper<PasswordResetToken> {
        @Override
        public PasswordResetToken mapRow(ResultSet rs, int rowNum) throws SQLException {
            PasswordResetToken token = new PasswordResetToken(rs.getString("token"), UUID.fromString(rs.getString("user_id")), rs.getTimestamp("expiry_date").toInstant());
            token.setId(UUID.fromString(rs.getString("id")));
            token.setUsed(rs.getBoolean("used"));
            if (rs.getTimestamp("used_at") != null) {
                token.setUsedAt(rs.getTimestamp("used_at").toInstant());
            }
            token.setCreatedAt(rs.getTimestamp("created_at").toInstant());
            return token;
        }
    }
}
