package com.ricardo.auth.service;

import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * The type User details service.
 */
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserService<User, Long> userService;

    /**
     * Instantiates a new User details service.
     *
     * @param userService the user service
     */
    public UserDetailsServiceImpl(UserService<User, Long> userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userService.getUserByEmail(email);
    }
}