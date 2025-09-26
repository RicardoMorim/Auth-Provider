package com.ricardo.auth.service;

import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.user.AppRole;
import com.ricardo.auth.domain.user.AuthUser;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * The type User details service.
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 *
 * @param <U>  the type parameter
 * @param <R>  the type parameter
 * @param <ID> the type parameter
 */
public class UserDetailsServiceImpl<U extends AuthUser<ID, R>, R extends AppRole, ID> implements UserDetailsService {

    private final UserService<U, R, ID> userService;

    /**
     * Instantiates a new User details service.
     *
     * @param userService the user service
     */
    public UserDetailsServiceImpl(UserService<U, R, ID> userService) {
        this.userService = userService;
    }

    /**
     * Load user by username user details.
     *
     * @param email the email
     * @return the user details
     * @throws UsernameNotFoundException the username not found exception
     */
    @Override
    @Cacheable(cacheNames = "userByEmail", key = "#email", condition = "#email != null")
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        if (email == null || email.isBlank()) {
            throw new UsernameNotFoundException("Email cannot be null or blank");
        }
        return userService.getUserByEmail(email);
    }
}