package com.ricardo.auth.dto;

import lombok.Data;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import java.util.List;

/**
 * Request DTO for bulk role operations.
 *
 */
@Data
public class BulkRoleUpdateRequest {

    private List<String> rolesToAdd;

    private List<String> rolesToRemove;
    @Size(max = 255, message = "Reason cannot exceed 255 characters")
    private String reason;

    /**
     * Validates that at least one operation is specified.
     */
    @jakarta.validation.constraints.AssertTrue(message = "Provide at least one of rolesToAdd or rolesToRemove")
    public boolean hasOperations() {
        return (rolesToAdd != null && !rolesToAdd.isEmpty()) ||
                (rolesToRemove != null && !rolesToRemove.isEmpty());
    }
}