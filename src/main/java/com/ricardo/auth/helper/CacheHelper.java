package com.ricardo.auth.helper;

import com.ricardo.auth.core.Role;
import com.ricardo.auth.domain.user.AuthUser;

/**
 * The interface Cache helper.
 *
 * @param <U>  the type parameter
 * @param <R>  the type parameter
 * @param <ID> the type parameter
 */
public interface CacheHelper<U extends AuthUser<ID, R>, R extends Role, ID> {

    /**
     * Evict user cache.
     *
     * @param user the user
     */
    void evictUserCache(U user);
}
