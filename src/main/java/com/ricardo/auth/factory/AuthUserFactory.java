package com.ricardo.auth.factory;


import com.ricardo.auth.core.Role;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.dto.CreateUserRequestDTO;

/**
 * Factory interface for creating AuthUser instances.
 * If you need to create another implemnetation of AuthUser, you can implement this interface.
 *
 * @param <U>  the type parameter
 * @param <R>  the type parameter
 * @param <ID> the type parameter
 */
public interface AuthUserFactory<U extends AuthUser<ID, R>, R extends Role, ID> {
    /**
     * Create u.
     *
     * @param request the request
     * @return the u
     */
    U create(CreateUserRequestDTO request);
}