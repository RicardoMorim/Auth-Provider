package com.ricardo.auth.repository.refreshToken;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.domain.refreshtoken.RefreshToken;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;

import javax.sql.DataSource;
import java.sql.*;
import java.time.Instant;
import java.util.Optional;

/**
 * The type Postgre sql refresh token repository.
 */
public class PostgreSQLRefreshTokenRepository implements RefreshTokenRepository {

    private final JdbcTemplate jdbcTemplate;
    private final String tableName = "refresh_tokens";

    /**
     * Instantiates a new Postgre sql refresh token repository.
     *
     * @param dataSource     the data source
     * @param authProperties the auth properties
     */
    public PostgreSQLRefreshTokenRepository(DataSource dataSource, AuthProperties authProperties) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @Override
    public Optional<RefreshToken> findByTokenRaw(String token) {
        String sql = String.format("SELECT * FROM %s WHERE token = ?", tableName);

        try {
            RefreshToken refreshToken = jdbcTemplate.queryForObject(sql,
                    new RefreshTokenRowMapper(), token);
            return Optional.ofNullable(refreshToken);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return findValidToken(token, Instant.now());
    }

    @Override
    public Optional<RefreshToken> findValidToken(String token, Instant now) {
        String sql = String.format("""
                SELECT * FROM %s 
                WHERE token = ? AND revoked = false AND expiry_date > ?
                """, tableName);

        try {
            RefreshToken refreshToken = jdbcTemplate.queryForObject(sql,
                    new RefreshTokenRowMapper(), token, Timestamp.from(now));
            return Optional.ofNullable(refreshToken);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    public RefreshToken saveToken(RefreshToken refreshToken) {
        if (refreshToken.getId() == null) {
            return insert(refreshToken);
        } else {
            return update(refreshToken);
        }
    }

    private RefreshToken insert(RefreshToken refreshToken) {
        String sql = String.format("""
                INSERT INTO %s (token, user_email, expiry_date, revoked, created_at) 
                VALUES (?, ?, ?, ?, ?) 
                RETURNING id
                """, tableName);

        KeyHolder keyHolder = new GeneratedKeyHolder();
        jdbcTemplate.update(connection -> {
            PreparedStatement ps = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            ps.setString(1, refreshToken.getToken());
            ps.setString(2, refreshToken.getUserEmail());
            ps.setTimestamp(3, Timestamp.from(refreshToken.getExpiryDate()));
            ps.setBoolean(4, refreshToken.isRevoked());
            ps.setTimestamp(5, Timestamp.from(refreshToken.getCreatedAt()));
            return ps;
        }, keyHolder);

        Long id = keyHolder.getKey().longValue();
        refreshToken.setId(id);
        return refreshToken;
    }

    private RefreshToken update(RefreshToken refreshToken) {
        String sql = String.format("""
                UPDATE %s 
                SET token = ?, user_email = ?, expiry_date = ?, revoked = ?
                WHERE id = ?
                """, tableName);

        int rowsAffected = jdbcTemplate.update(sql,
                refreshToken.getToken(),
                refreshToken.getUserEmail(),
                Timestamp.from(refreshToken.getExpiryDate()),
                refreshToken.isRevoked(),
                refreshToken.getId()
        );

        if (rowsAffected == 0) {
            throw new RuntimeException("Failed to update refresh token with id: " + refreshToken.getId());
        }

        return refreshToken;
    }

    @Override
    public void deleteByToken(String token) {
        String sql = String.format("DELETE FROM %s WHERE token = ?", tableName);
        jdbcTemplate.update(sql, token);
    }

    @Override
    public boolean existsByToken(String token) {
        String sql = String.format("""
                SELECT COUNT(*) FROM %s 
                WHERE token = ? AND revoked = false AND expiry_date > NOW()
                """, tableName);
        Integer count = jdbcTemplate.queryForObject(sql, Integer.class, token);
        return count != null && count > 0;
    }

    @Override
    public void revokeAllUserTokens(String userEmail) {
        String sql = String.format("UPDATE %s SET revoked = true WHERE user_email = ?", tableName);
        jdbcTemplate.update(sql, userEmail);
    }

    @Override
    public int deleteExpiredTokens(Instant now) {
        String sql = String.format("DELETE FROM %s WHERE expiry_date < ?", tableName);
        return jdbcTemplate.update(sql, Timestamp.from(now));
    }

    @Override
    public void deleteByUserEmailAndExpiryDateBefore(String userEmail, Instant expiryDate) {
        String sql = String.format("DELETE FROM %s WHERE user_email = ? AND expiry_date < ?", tableName);
        jdbcTemplate.update(sql, userEmail, Timestamp.from(expiryDate));
    }

    @Override
    public long countByUserEmailAndRevokedFalseAndExpiryDateAfter(String userEmail, Instant now) {
        String sql = String.format("""
                SELECT COUNT(*) FROM %s 
                WHERE user_email = ? AND revoked = false AND expiry_date > ?
                """, tableName);
        Long count = jdbcTemplate.queryForObject(sql, Long.class, userEmail, Timestamp.from(now));
        return count != null ? count : 0;
    }

    @Override
    public int deleteByUserEmail(String userEmail) {
        if (userEmail == null || userEmail.trim().isEmpty()) {
            return 0;
        }

        String sql = "DELETE FROM refresh_tokens WHERE user_email = ?";
        return jdbcTemplate.update(sql, userEmail);
    }

    @Override
    public int deleteOldestTokensForUser(String userEmail, int maxTokens) {
        if (userEmail == null || userEmail.trim().isEmpty()) {
            return 0;
        }

        // First check if we need to delete anything
        String countSql = "SELECT COUNT(*) FROM refresh_tokens WHERE user_email = ?";
        Integer currentCount = jdbcTemplate.queryForObject(countSql, Integer.class, userEmail);

        if (currentCount == null || currentCount <= maxTokens) {
            return 0;
        }

        int tokensToDelete = currentCount - maxTokens;

        String sql = """
                DELETE FROM refresh_tokens 
                WHERE user_email = ? 
                AND id IN (
                    SELECT id FROM (
                        SELECT id FROM refresh_tokens 
                        WHERE user_email = ? 
                        ORDER BY created_at ASC 
                        LIMIT ?
                    ) AS subquery
                )
                """;
        return jdbcTemplate.update(sql, userEmail, userEmail, tokensToDelete);
    }

    @Override
    public int countActiveTokensByUser(String userEmail) {
        if (userEmail == null || userEmail.trim().isEmpty()) {
            return 0;
        }

        String sql = "SELECT COUNT(*) FROM refresh_tokens WHERE user_email = ? AND revoked = false AND expiry_date > ?";
        Integer count = jdbcTemplate.queryForObject(sql, Integer.class, userEmail, Timestamp.from(Instant.now()));
        return count != null ? count : 0;
    }

    @Override
    public void deleteAll() {
        String sql = String.format("DELETE FROM %s", tableName);
        jdbcTemplate.update(sql);
    }

    private static class RefreshTokenRowMapper implements RowMapper<RefreshToken> {
        /**
         * Map row refresh token.
         *
         * @param rs     the rs
         * @param rowNum the row num
         * @return the refresh token
         * @throws SQLException the sql exception
         */
        @Override
        public RefreshToken mapRow(ResultSet rs, int rowNum) throws SQLException {
            RefreshToken token = new RefreshToken(
                    rs.getString("token"),
                    rs.getString("user_email"),
                    rs.getTimestamp("expiry_date").toInstant()
            );
            token.setId(rs.getLong("id"));
            token.setRevoked(rs.getBoolean("revoked"));
            token.setCreatedAt(rs.getTimestamp("created_at").toInstant());
            return token;
        }
    }
}