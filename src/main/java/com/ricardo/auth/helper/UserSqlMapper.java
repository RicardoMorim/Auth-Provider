package com.ricardo.auth.helper;

import com.ricardo.auth.domain.user.User;

/**
 * The type User sql mapper.
 */
public class UserSqlMapper implements UserSqlParameterMapper<User> {

    @Override
    public String getInsertSql() {
        return "INSERT INTO users (email, username, password, version, created_at, updated_at) VALUES (?, ?, ?, 0, NOW(), NOW()) RETURNING id";
    }

    @Override
    public Object[] getInsertParams(User user) {
        return new Object[]{
                user.getEmail(),
                user.getUsername(),
                user.getPassword()
        };
    }

    @Override
    public String getInsertRolesSql() {
        return "INSERT INTO user_roles (user_id, role) VALUES (?, ?)";
    }

    @Override
    public Object[][] getInsertRolesParams(User user) {
        if (user.getId() == null || user.getRoles() == null || user.getRoles().isEmpty()) {
            return new Object[0][0];
        }
        Object[][] params = new Object[user.getRoles().size()][2];
        int i = 0;
        for (var role : user.getRoles()) {
            params[i][0] = user.getId();
            params[i][1] = role.name();
            i++;
        }
        return params;
    }
}
