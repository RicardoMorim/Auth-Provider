package com.ricardo.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

/**
 * Response DTO for user roles information.
 * 
 * @since 3.1.0
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
     */
    public UserRolesResponse(String userId, String username, List<String> roles) {
        this.userId = userId;
        this.username = username;
        this.roles = roles;
    }
}
