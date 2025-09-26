package com.ricardo.auth.repository.refreshToken;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.domain.refreshtoken.RefreshToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.transaction.annotation.Transactional;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * The type Postgre sql refresh token repository.
 */
public class PostgreSQLRefreshTokenRepository implements RefreshTokenRepository {

    private static final Logger logger = LoggerFactory.getLogger(PostgreSQLRefreshTokenRepository.class);
    private final JdbcTemplate jdbcTemplate;
    private final String tableName = "refresh_tokens";

    /**
     * Instantiates a new Postgre sql refresh token repository.
     *
     * @param jdbcTemplate   the data source
     * @param authProperties the auth properties
     */
    public PostgreSQLRefreshTokenRepository(JdbcTemplate jdbcTemplate, AuthProperties authProperties) {
        this.jdbcTemplate = jdbcTemplate;
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
            return updateWithOptimisticLocking(refreshToken);
        }
    }

    private RefreshToken insert(RefreshToken refreshToken) {
        String sql = String.format("""
                INSERT INTO %s (token, user_email, expiry_date, revoked, created_at, version) 
                VALUES (?, ?, ?, ?, ?, 0) RETURNING id
                """, tableName);

        Object generatedId = jdbcTemplate.queryForObject(sql, Object.class,
                refreshToken.getToken(),
                refreshToken.getUserEmail(),
                Timestamp.from(refreshToken.getExpiryDate()),
                refreshToken.isRevoked(),
                Timestamp.from(refreshToken.getCreatedAt())
        );

        if (generatedId instanceof UUID uuid) {
            refreshToken.setId(uuid);
        } else if (generatedId instanceof String uuidStr) {
            refreshToken.setId(UUID.fromString(uuidStr));
        } else {
            throw new IllegalArgumentException("Invalid ID type returned");
        }

        refreshToken.setVersion(0L); // Set initial version
        return refreshToken;
    }

    private RefreshToken updateWithOptimisticLocking(RefreshToken refreshToken) {
        String sql = String.format("""
                UPDATE %s 
                SET token = ?, user_email = ?, expiry_date = ?, revoked = ?, version = version + 1
                WHERE id = ? AND version = ?
                """, tableName);

        int rowsAffected = jdbcTemplate.update(sql,
                refreshToken.getToken(),
                refreshToken.getUserEmail(),
                Timestamp.from(refreshToken.getExpiryDate()),
                refreshToken.isRevoked(),
                refreshToken.getId(),
                refreshToken.getVersion()
        );

        if (rowsAffected == 0) {
            throw new ObjectOptimisticLockingFailureException(RefreshToken.class,
                    "RefreshToken with id " + refreshToken.getId() + " and version " + refreshToken.getVersion() +
                            " was not found or has been modified by another transaction"
            );
        }

        // Increment version locally
        refreshToken.setVersion(refreshToken.getVersion() + 1);
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
        // Use PostgreSQL's UPDATE with RETURNING for better performance
        String sql = String.format("""
                UPDATE %s 
                SET revoked = true, version = version + 1 
                WHERE user_email = ? AND revoked = false
                RETURNING id
                """, tableName);

        List<UUID> revokedIds = jdbcTemplate.queryForList(sql, UUID.class, userEmail);
        logger.debug("Revoked {} tokens for user: {}", revokedIds.size(), userEmail);
    }

    @Override
    public int deleteExpiredTokens(Instant now) {
        // Use PostgreSQL's efficient bulk delete with LIMIT for large datasets
        String sql = String.format("""
                WITH deleted AS (
                    DELETE FROM %s 
                    WHERE expiry_date < ? 
                    RETURNING id
                )
                SELECT count(*) FROM deleted
                """, tableName);

        Integer deletedCount = jdbcTemplate.queryForObject(sql, Integer.class, Timestamp.from(now));
        return deletedCount != null ? deletedCount : 0;
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
        if (userEmail == null || userEmail.trim().isEmpty())
            return 0;
        String sql = String.format("""
                WITH to_keep AS (
                    SELECT id FROM %s
                    WHERE user_email = ?
                    ORDER BY created_at DESC
                    LIMIT ? 
                ),
                deleted AS (
                    DELETE FROM %s
                    WHERE user_email = ? AND id NOT IN (SELECT id FROM to_keep)
                    RETURNING id
                )
                SELECT count(*) FROM deleted
                """, tableName, tableName);

        Integer deletedCount = jdbcTemplate.queryForObject(sql, Integer.class,
                userEmail, maxTokens, userEmail);
        return deletedCount != null ? deletedCount : 0;
    }

    /**
     * Save all tokens list.
     *
     * @param tokens the tokens
     * @return the list
     */
    @Transactional
    public List<RefreshToken> saveAllTokens(List<RefreshToken> tokens) {
        List<RefreshToken> toInsert = new ArrayList<>();
        List<RefreshToken> toUpdate = new ArrayList<>();

        // Separate inserts from updates
        for (RefreshToken token : tokens) {
            if (token.getId() == null) {
                toInsert.add(token);
            } else {
                toUpdate.add(token);
            }
        }

        List<RefreshToken> result = new ArrayList<>();

        // Batch insert new tokens
        if (!toInsert.isEmpty()) {
            result.addAll(batchInsertTokens(toInsert));
        }

        // Update existing tokens (with optimistic locking)
        for (RefreshToken token : toUpdate) {
            result.add(updateWithOptimisticLocking(token));
        }

        return result;
    }

    private List<RefreshToken> batchInsertTokens(List<RefreshToken> tokens) {
        if (tokens.isEmpty()) {
            return tokens;
        }

        // Build the VALUES clause for all tokens
        StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append(String.format("""
                INSERT INTO %s (token, user_email, expiry_date, revoked, created_at, version) 
                VALUES 
                """, tableName));

        List<Object> parameters = new ArrayList<>();

        // Add VALUES clauses for each token
        for (int i = 0; i < tokens.size(); i++) {
            if (i > 0) {
                sqlBuilder.append(", ");
            }
            sqlBuilder.append("(?, ?, ?, ?, ?, 0)");

            RefreshToken token = tokens.get(i);
            parameters.add(token.getToken());
            parameters.add(token.getUserEmail());
            parameters.add(Timestamp.from(token.getExpiryDate()));
            parameters.add(token.isRevoked());
            parameters.add(Timestamp.from(token.getCreatedAt()));
        }

        sqlBuilder.append(" RETURNING id, token");

        // Execute the query and map returned IDs back to tokens
        List<TokenIdMapping> idMappings = jdbcTemplate.query(
                sqlBuilder.toString(),
                parameters.toArray(),
                (rs, rowNum) -> new TokenIdMapping(
                        (UUID) rs.getObject("id"),
                        rs.getString("token")
                )
        );

        // Map returned IDs back to the original tokens by matching token values
        for (RefreshToken token : tokens) {
            TokenIdMapping mapping = idMappings.stream()
                    .filter(m -> m.token().equals(token.getToken()))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException(
                            "Could not find returned ID for token: " + token.getToken()));

            token.setId(mapping.id());
            token.setVersion(0L);
        }

        return tokens;
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

    // Helper record for mapping returned IDs to tokens
    private record TokenIdMapping(UUID id, String token) {
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
            Object id = rs.getObject("id");
            if (!(id instanceof UUID)) {
                throw new SQLException("Expected UUID for id, but got: " + id.getClass().getName());
            }
            token.setId((UUID) id);
            token.setRevoked(rs.getBoolean("revoked"));
            token.setCreatedAt(rs.getTimestamp("created_at").toInstant());

            // Map version if it exists
            try {
                Long version = rs.getLong("version");
                token.setVersion(version);
            } catch (SQLException e) {
                // Version column might not exist in older schemas
                token.setVersion(0L);
            }

            return token;
        }
    }
}
