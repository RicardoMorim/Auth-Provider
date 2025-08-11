package com.ricardo.auth.helper;

import com.ricardo.auth.domain.user.AuthUser;

public interface UserSqlParameterMapper<T extends AuthUser<?, ?>> {
    String getInsertSql();
    Object[] getInsertParams(T user);
    String getInsertRolesSql();
    Object[][] getInsertRolesParams(T user);
}