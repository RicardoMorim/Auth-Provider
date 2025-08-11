package com.ricardo.auth.factory;


import com.ricardo.auth.core.Role;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.dto.CreateUserRequestDTO;

import java.util.Set;

/**
 * Factory interface for creating AuthUser instances.
 * If you need to create another implemnetation of AuthUser, you can implement this interface.
 *
 * @param <U>
 */
public interface AuthUserFactory<U extends AuthUser<ID, R>, R extends Role, ID> {
    U create(CreateUserRequestDTO request);
}