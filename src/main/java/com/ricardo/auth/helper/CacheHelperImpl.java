package com.ricardo.auth.helper;

import com.ricardo.auth.core.Role;
import com.ricardo.auth.domain.user.AuthUser;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;


@AllArgsConstructor
public class CacheHelperImpl<U extends AuthUser<ID, R>, R extends Role, ID> implements CacheHelper<U, R, ID>{

    private CacheManager cacheHelper;

    private void evictCache(String cacheName, Object key) {
        Cache cache = cacheHelper.getCache(cacheName);
        if (cache != null) {
            cache.evict(key);
        }
    }

    private void clearCache(String cacheName) {
        Cache cache = cacheHelper.getCache(cacheName);
        if (cache != null) {
            cache.clear();
        }
    }

    @Override
    public void evictUserCache(U user) {
        evictCache("userById", user.getId());
        evictCache("userByEmail", user.getEmail());
        evictCache("userByUsername", user.getUsername());
        evictCache("userExists", user.getEmail());

        Collection<? extends GrantedAuthority> auths = user.getAuthorities();

        if (auths != null) {
            for (GrantedAuthority auth : auths) {
                if (auth != null && auth.getAuthority() != null) {
                    evictCache("usersByRole", auth.getAuthority());
                    evictCache("userHasRoleCache", user.getId().toString() + "::" + auth.getAuthority());
                    evictCache("getUserRolesCache", user.getId());
                }
            }
        }

        clearCache("users");
    }
}
