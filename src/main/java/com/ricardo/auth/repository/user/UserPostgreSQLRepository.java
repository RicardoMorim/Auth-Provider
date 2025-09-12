package com.ricardo.auth.repository.user;

import com.ricardo.auth.core.Role;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.domain.user.AppRole;
import com.ricardo.auth.helper.IdConverter;
import com.ricardo.auth.helper.RoleMapper;
import com.ricardo.auth.helper.UserRowMapper;
import com.ricardo.auth.helper.UserSqlParameterMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.ObjectOptimisticLockingFailureException;

import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.util.*;

@Repository
public class UserPostgreSQLRepository<T extends AuthUser<ID, R>, R extends Role, ID> implements UserRepository<T, R, ID> {
    
    private static final Logger logger = LoggerFactory.getLogger(UserPostgreSQLRepository.class);

    private final UserRowMapper<T, R, ID> userRowMapper;
    private final UserSqlParameterMapper<T> userSqlParameterMapper;
    private final RoleMapper<R> roleMapper;
    private final JdbcTemplate jdbcTemplate;
    private final IdConverter<ID> idConverter;

    public UserPostgreSQLRepository(UserRowMapper<T, R, ID> userRowMapper,
                                    UserSqlParameterMapper<T> userSqlParameterMapper,
                                    RoleMapper<R> roleMapper,
                                    IdConverter<ID> idConverter,
                                    DataSource dataSource) {
        this.userRowMapper = userRowMapper;
        this.userSqlParameterMapper = userSqlParameterMapper;
        this.roleMapper = roleMapper;
        this.jdbcTemplate = new JdbcTemplate(dataSource);
        this.idConverter = idConverter;
    }

    @Override
    public Optional<T> findByEmail(String email) {
        String sql = """
            SELECT u.*, ur.role 
            FROM users u 
            LEFT JOIN user_roles ur ON u.id = ur.user_id 
            WHERE u.email = ?
            """;

        return findUserWithRoles(sql, email);
    }

    @Override
    public Optional<T> findByUsername(String username) {
        String sql = """
            SELECT u.*, ur.role 
            FROM users u 
            LEFT JOIN user_roles ur ON u.id = ur.user_id 
            WHERE u.username = ?
            """;

        return findUserWithRoles(sql, username);
    }

    @Override
    public boolean existsByEmail(String email) {
        String sql = "SELECT COUNT(*) FROM users WHERE email = ?";
        Integer count = jdbcTemplate.queryForObject(sql, Integer.class, email);
        return count != null && count > 0;
    }

    @Override
    public boolean existsByUsername(String username) {
        String sql = "SELECT COUNT(*) FROM users WHERE username = ?";
        Integer count = jdbcTemplate.queryForObject(sql, Integer.class, username);
        return count != null && count > 0;
    }

    @Override
    public boolean existsById(ID id) {
        String sql = "SELECT COUNT(*) FROM users WHERE id = ?";
        Integer count = jdbcTemplate.queryForObject(sql, Integer.class, id);
        return count != null && count > 0;
    }

    @Override
    public long count() {
        String sql = "SELECT COUNT(*) FROM users";
        Long count = jdbcTemplate.queryForObject(sql, Long.class);
        return count != null ? count : 0;
    }

    @Override
    public <S extends T> S saveUser(S entity) {
        if (entity.getId() == null) {
            // Insert new user
            return insertUser(entity);
        } else {
            // Update existing user with optimistic locking
            return updateUser(entity);
        }
    }

    private <S extends T> S insertUser(S entity) {
        // Insert the user using RETURNING to get the generated ID
        String userSql = userSqlParameterMapper.getInsertSql();
        Object[] userParams = userSqlParameterMapper.getInsertParams(entity);

        // Execute and get the returned UUID
        Object generatedId = jdbcTemplate.queryForObject(userSql, userParams, Object.class);

        if (generatedId == null) {
            throw new IllegalStateException("Failed to generate ID for new user");
        }

        String stringId;

        if (generatedId instanceof String){
            try {
                stringId = (String) generatedId;
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException("Generated ID is not a valid UUID: " + generatedId, e);
            }
        } else if (!(generatedId instanceof UUID)) {
            throw new IllegalStateException("Generated ID is not of type UUID: " + generatedId.getClass().getName());
        } else {
            stringId = ((UUID) generatedId).toString();
        }

        ID id = idConverter.fromString(stringId);

        entity.setId(id);
        entity.setVersion(0L); // Set initial version

        // Now insert the roles if any using COPY for better performance
        insertUserRoles(entity);

        return entity;
    }

    private <S extends T> S updateUser(S entity) {
        // Use optimistic locking with version
        String sql = """
            UPDATE users 
            SET username = ?, email = ?, password = ?, version = version + 1, updated_at = NOW()
            WHERE id = ? AND version = ?
            """;

        int rowsAffected = jdbcTemplate.update(sql,
                entity.getUsername(),
                entity.getEmail(),
                entity.getPassword(),
                entity.getId(),
                entity.getVersion()
        );

        if (rowsAffected == 0) {
            throw new ObjectOptimisticLockingFailureException(
                "User with id " + entity.getId() + " and version " + entity.getVersion() +
                " was not found or has been modified by another transaction", entity
            );
        }
        // Increment version locally
        entity.setVersion(entity.getVersion() + 1);
        entity.setUpdatedAt(java.time.Instant.now());

        // Update roles efficiently
        updateUserRoles(entity);

        return entity;
    }

    private <S extends T> void insertUserRoles(S entity) {
        Object[][] rolesParams = userSqlParameterMapper.getInsertRolesParams(entity);
        if (rolesParams.length > 0) {
            String rolesSql = userSqlParameterMapper.getInsertRolesSql();
            List<Object[]> rolesList = Arrays.asList(rolesParams);
            jdbcTemplate.batchUpdate(rolesSql, rolesList);
        }
    }

    private <S extends T> void updateUserRoles(S entity) {
        // First, delete existing roles for this user
        String deleteRolesSql = "DELETE FROM user_roles WHERE user_id = ?";
        jdbcTemplate.update(deleteRolesSql, entity.getId());

        // Then insert new roles
        insertUserRoles(entity);
    }

    // Optimized bulk operations
    @Override
    public <S extends T> List<S> saveAll(Iterable<S> entities) {
        List<S> result = new ArrayList<>();
        List<S> toInsert = new ArrayList<>();
        List<S> toUpdate = new ArrayList<>();

        // Separate inserts from updates
        for (S entity : entities) {
            if (entity.getId() == null) {
                toInsert.add(entity);
            } else {
                toUpdate.add(entity);
            }
        }

        // Batch insert new users
        if (!toInsert.isEmpty()) {
            result.addAll(batchInsertUsers(toInsert));
        }

        // Update existing users one by one (due to optimistic locking)
        for (S entity : toUpdate) {
            result.add(updateUser(entity));
        }

        return result;
    }

    private <S extends T> List<S> batchInsertUsers(List<S> entities) {
        List<S> result = new ArrayList<>();

        for (S entity : entities) {
            result.add(insertUser(entity));
        }

        return result;
    }

    @Override
    public Optional<T> findById(ID id) {
        String sql = """
            SELECT u.*, ur.role 
            FROM users u 
            LEFT JOIN user_roles ur ON u.id = ur.user_id 
            WHERE u.id = ?
            """;

        return findUserWithRoles(sql, id);
    }

    @Override
    public List<T> findAll() {
        String sql = """
            SELECT u.*, ur.role 
            FROM users u 
            LEFT JOIN user_roles ur ON u.id = ur.user_id 
            ORDER BY u.id
            """;

        return findUsersWithRoles(sql);
    }

    @Override
    public List<T> findAllById(Iterable<ID> ids) {
        StringBuilder sql = new StringBuilder("""
            SELECT u.*, ur.role 
            FROM users u 
            LEFT JOIN user_roles ur ON u.id = ur.user_id 
            WHERE u.id IN (
            """);

        List<Object> params = new ArrayList<>();
        for (ID id : ids) {
            sql.append("?,");
            params.add(id);
        }
        if (params.isEmpty()) return List.of();
        sql.setLength(sql.length() - 1); // remove last comma
        sql.append(") ORDER BY u.id");

        return findUsersWithRoles(sql.toString(), params.toArray());
    }

    @Override
    public void deleteById(ID id) {
        // First delete the roles
        String deleteRolesSql = "DELETE FROM user_roles WHERE user_id = ?";
        jdbcTemplate.update(deleteRolesSql, id);

        // Then delete the user
        String sql = "DELETE FROM users WHERE id = ?";
        jdbcTemplate.update(sql, id);
    }

    @Override
    public void delete(T entity) {
        if (entity.getId() != null) {
            @SuppressWarnings("unchecked")
            ID id = (ID) entity.getId();
            deleteById(id);
        }
    }

    @Override
    public void deleteAllById(Iterable<? extends ID> ids) {
        for (ID id : ids) {
            deleteById(id);
        }
    }

    @Override
    public void deleteAll(Iterable<? extends T> entities) {
        for (T entity : entities) {
            delete(entity);
        }
    }

    @Override
    public void deleteAll() {
        // First delete all roles
        String deleteAllRolesSql = "DELETE FROM user_roles";
        jdbcTemplate.update(deleteAllRolesSql);

        // Then delete all users
        String sql = "DELETE FROM users";
        jdbcTemplate.update(sql);
    }


    @Override
    public int countUsers(){
        String countSql = "SELECT COUNT(*) FROM users";
        Integer count = jdbcTemplate.queryForObject(countSql, Integer.class);
        return count != null ? count : 0;
    }


    @Override
    public int countUsersByRole(String Role){
        String countSql = """
            SELECT COUNT(DISTINCT u.id) 
            FROM users u 
            JOIN user_roles ur ON u.id = ur.user_id 
            WHERE ur.role = ?
            """;
        Integer count = jdbcTemplate.queryForObject(countSql, Integer.class, Role);
        return count != null ? count : 0;
    }


    // Helper methods to aggregate roles
    @SuppressWarnings("unchecked")
    private Optional<T> findUserWithRoles(String sql, Object... params) {
        Map<Object, T> userMap = new HashMap<>();
        jdbcTemplate.query(sql, rs -> {
            Object userId = rs.getObject("id");
            T user = userMap.get(userId);
            if (user == null) {
                user = userRowMapper.mapRow(rs, 0);
                userMap.put(userId, user);
            } else {
                // Add additional roles to existing user
                String roleStr = rs.getString("role");
                if (roleStr != null && !roleStr.trim().isEmpty()) {
                    try {
                        R role = roleMapper.mapRole(roleStr.trim());
                        user.addRole(role);
                    } catch (RoleMapper.RoleMappingException e) {
                        logger.warn("Failed to map role '{}' for user ID '{}': {}", roleStr, userId, e.getMessage());
                        // Skip invalid roles but continue processing
                    } catch (Exception e) {
                        logger.error("Unexpected error mapping role '{}' for user ID '{}': {}", roleStr, userId, e.getMessage(), e);
                        // Skip invalid roles but continue processing
                    }
                }
            }
        }, params);

        return userMap.values().stream().findFirst();
    }
    @SuppressWarnings("unchecked")
    private List<T> findUsersWithRoles(String sql, Object... params) {
        Map<Object, T> userMap = new LinkedHashMap<>();
        jdbcTemplate.query(sql, rs -> {
            Object userId = rs.getObject("id");
            T user = userMap.get(userId);
            if (user == null) {
                user = userRowMapper.mapRow(rs, 0);
                userMap.put(userId, user);
            } else {
                // Add additional roles to existing user
                String roleStr = rs.getString("role");
                if (roleStr != null && !roleStr.trim().isEmpty()) {
                    try {
                        R role = roleMapper.mapRole(roleStr.trim());
                        user.addRole(role);
                    } catch (RoleMapper.RoleMappingException e) {
                        logger.warn("Failed to map role '{}' for user ID '{}': {}", roleStr, userId, e.getMessage());
                        // Skip invalid roles but continue processing
                    } catch (Exception e) {
                        logger.error("Unexpected error mapping role '{}' for user ID '{}': {}", roleStr, userId, e.getMessage(), e);
                        // Skip invalid roles but continue processing
                    }
                }
            }
        }, params);

        return new ArrayList<>(userMap.values());
    }
}
