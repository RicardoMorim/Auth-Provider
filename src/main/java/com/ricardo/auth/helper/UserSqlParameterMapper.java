package com.ricardo.auth.helper;

import com.ricardo.auth.domain.user.AuthUser;

/**
 * The interface User sql parameter mapper.
 *
 * @param <T> the type parameter
 */
public interface UserSqlParameterMapper<T extends AuthUser<?, ?>> {
    /**
     * Gets insert sql.
     *
     * @return the insert sql
     */
    String getInsertSql();

    /**
     * Get insert params object [ ].
     *
     * @param user the user
     * @return the object [ ]
     */
    Object[] getInsertParams(T user);

    /**
     * Gets insert roles sql.
     *
     * @return the insert roles sql
     */
    String getInsertRolesSql();

    /**
     * Get insert roles params object [ ] [ ].
     *
     * @param user the user
     * @return the object [ ] [ ]
     */
    Object[][] getInsertRolesParams(T user);
}