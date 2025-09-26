package com.ricardo.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO for removing a role from a user.
 *
 */
@AllArgsConstructor
@NoArgsConstructor
@Data
public class RemoveRoleRequest {

    @NotBlank(message = "Role name is required")
    @Size(max = 50, message = "Role name cannot exceed 50 characters")
    private String roleName;

    @Size(max = 255, message = "Reason cannot exceed 255 characters")
    private String reason;
}
