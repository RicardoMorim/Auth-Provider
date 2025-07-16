package com.ricardo.auth.config;

import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import com.ricardo.auth.domain.user.User;
import org.springframework.stereotype.Service;

/**
 * The type User security service.
 */
@Service
public class UserSecurityService {

    private final UserService<User, Long> userService;

    /**
     * Instantiates a new User security service.
     *
     * @param userService the user service
     */
    public UserSecurityService(UserService<User, Long> userService) {
        this.userService = userService;
    }

    /**
     * Is owner boolean.
     *
     * @param email  the email
     * @param userId the user id
     * @return the boolean
     */
    public boolean isOwner(String email, Long userId) {
        try {
            User user = userService.getUserById(userId);
            return user.getEmail().equals(email);
        } catch (ResourceNotFoundException e) {
            return false;
        }
    }
}