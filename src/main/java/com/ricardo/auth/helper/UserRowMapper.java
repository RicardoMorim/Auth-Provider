package com.ricardo.auth.helper;

import com.ricardo.auth.core.Role;
import com.ricardo.auth.domain.user.AuthUser;

import java.sql.ResultSet;

public interface UserRowMapper<T extends AuthUser<ID, R>, R extends Role, ID> {
    /**
     * Maps a row from the database to a User object.
     *
     * @param rs     the ResultSet containing the row data
     * @param rowNum the number of the current row
     *
     * @return the mapped User object
     */
    T mapRow(ResultSet rs, int rowNum);
}
