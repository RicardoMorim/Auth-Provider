package com.ricardo.auth.config;

import com.ricardo.auth.core.Role;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.helper.IdConverter;
import org.springframework.stereotype.Service;

/**
 * The type User security service.
 */
@Service
public class UserSecurityService<U extends AuthUser<ID, R>, R extends Role, ID> {

    private final UserService<U, R, ID> userService;
    private final IdConverter<ID> idConverter;

    /**
     * Instantiates a new User security service.
     *
     * @param userService the user service
     */
    public UserSecurityService(UserService<U, R, ID> userService, IdConverter<ID> idConverter) {
        this.userService = userService;
        this.idConverter = idConverter;
    }

    /**
     * Is owner boolean.
     *
     * @param email  the email
     * @param userId the user id
     * @return the boolean
     */
    public boolean isOwner(String email, String userId) {
        try {
            ID id = idConverter.fromString(userId);
            U user = userService.getUserById(id);
            return user.getEmail().equals(email);
        } catch (ResourceNotFoundException e) {
            return false;
        }
    }
}