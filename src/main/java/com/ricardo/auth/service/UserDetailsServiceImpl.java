package com.ricardo.auth.service;

import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.user.AppRole;
import com.ricardo.auth.domain.user.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.UUID;

/**
 * The type User details service.
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 */
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserService<User, AppRole, UUID> userService;

    /**
     * Instantiates a new User details service.
     *
     * @param userService the user service
     */
    public UserDetailsServiceImpl(UserService<User, AppRole, UUID> userService) {
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
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userService.getUserByEmail(email);
    }
}