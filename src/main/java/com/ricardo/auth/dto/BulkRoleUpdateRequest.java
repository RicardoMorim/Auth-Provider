package com.ricardo.auth.dto;

import lombok.Data;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import java.util.List;

/**
 * Request DTO for bulk role operations.
 * 
 * @since 3.1.0
 */
@Data
public class BulkRoleUpdateRequest {

    @NotEmpty(message = "At least one role operation is required")
    private List<String> rolesToAdd;

    @NotEmpty(message = "At least one role operation is required")
    private List<String> rolesToRemove;

    @Size(max = 255, message = "Reason cannot exceed 255 characters")
    private String reason;

    /**
     * Validates that at least one operation is specified.
     */
    public boolean hasOperations() {
        return (rolesToAdd != null && !rolesToAdd.isEmpty()) || 
               (rolesToRemove != null && !rolesToRemove.isEmpty());
    }
}
