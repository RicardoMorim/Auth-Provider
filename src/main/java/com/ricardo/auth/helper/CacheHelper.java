package com.ricardo.auth.helper;

import com.ricardo.auth.core.Role;
import com.ricardo.auth.domain.user.AuthUser;

public interface CacheHelper<U extends AuthUser<ID, R>, R extends Role, ID> {

    void evictUserCache(U user);
}
