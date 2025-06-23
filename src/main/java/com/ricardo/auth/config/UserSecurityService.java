package com.ricardo.auth.config;

import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.User;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserSecurityService {

    private final UserService<User, Long> userService;

    public UserSecurityService(UserService<User, Long> userService) {
        this.userService = userService;
    }

    public boolean isOwner(String email, Long userId) {
        try {
            User user = userService.getUserById(userId);
            return user.getEmail().equals(email);
        } catch (ResourceNotFoundException e) {
            return false;
        }
    }
}