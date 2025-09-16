package com.ricardo.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Response DTO for user roles information.
 *
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserRolesResponse {

    private String userId;
    private String username;
    private String email;
    private List<String> roles;

    /**
     * Constructor for basic role information.
     *
     * @param userId   the user id
     * @param username the username
     * @param roles    the roles
     */
    public UserRolesResponse(String userId, String username, List<String> roles) {
        this.userId = userId;
        this.username = username;
        this.roles = roles;
    }
}
