package com.ricardo.auth.helper;

import com.ricardo.auth.domain.user.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

@Slf4j
public class UserRowMapperImpl implements UserRowMapper<User, AppRole, UUID> {

    IdConverter<UUID> idConverter;

    public UserRowMapperImpl(IdConverter<UUID> idConverter) {
        this.idConverter = idConverter;
    }

    @Override
    public User mapRow(ResultSet rs, int rowNum) {
        try {
            Object userId = rs.getObject("id");
            User user = new User(
                    Username.valueOf(rs.getString("username")),
                    Email.valueOf(rs.getString("email")),
                    Password.fromHash(rs.getString("password"))
            );

            if (userId == null) {
                throw new SQLException("User ID is null in the result set");
            }

            UUID id;

            if (userId instanceof String stringId) {
                id = idConverter.fromString(stringId);
            }
            else if (userId instanceof UUID) {
                id = (UUID) userId;
            } else {
                throw new SQLException("Unexpected type for user ID: " + userId.getClass().getName());
            }


            user.setId(id);

            // Map version
            try {
                Long version = rs.getLong("version");
                user.setVersion(version);
            } catch (SQLException e) {
                user.setVersion(0L);
            }

            // Map timestamps
            try {
                Timestamp createdAt = rs.getTimestamp("created_at");
                if (createdAt != null) {
                    user.setCreatedAt(createdAt.toInstant());
                }

                Timestamp updatedAt = rs.getTimestamp("updated_at");
                if (updatedAt != null) {
                    user.setUpdatedAt(updatedAt.toInstant());
                }
            } catch (SQLException e) {
                // Timestamps might not exist in older schemas
                user.setCreatedAt(Instant.now());
                user.setUpdatedAt(Instant.now());
            }

            // Initialize with empty roles set - roles will be added by the repository
            user.setRoles(new java.util.HashSet<>());

            // Add the role from this row if it exists
            String roleStr = rs.getString("role");
            if (roleStr != null && !roleStr.trim().isEmpty()) {
                String normalizedRole = roleStr.trim().toUpperCase(java.util.Locale.ROOT);
                try {
                    user.addRole(AppRole.valueOf(normalizedRole));
                } catch (IllegalArgumentException ex) {
                    log.warn("Unknown role value '{}' for user '{}'", normalizedRole, user.getUsername());
                }
            }
            return user;
        } catch (SQLException e) {
            throw new RuntimeException("Error mapping row to User", e);
        }
    }
}
