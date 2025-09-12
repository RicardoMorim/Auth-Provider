package com.ricardo.auth.dto;

import lombok.Data;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request DTO for adding a role to a user.
 * 
 * @since 3.1.0
 */
@Data
public class AddRoleRequest {

    @NotBlank(message = "Role name is required")
    @Size(max = 50, message = "Role name cannot exceed 50 characters")
    private String roleName;

    @Size(max = 255, message = "Reason cannot exceed 255 characters")
    private String reason;
}
