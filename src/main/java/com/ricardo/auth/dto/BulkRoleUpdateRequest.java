package com.ricardo.auth.dto;

import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Request DTO for bulk role operations.
 *
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class BulkRoleUpdateRequest {

    private List<String> rolesToAdd;

    private List<String> rolesToRemove;
    @Size(max = 255, message = "Reason cannot exceed 255 characters")
    private String reason;

    /**
     * Validates that at least one operation is specified.
     *
     * @return the boolean
     */
    @jakarta.validation.constraints.AssertTrue(message = "Provide at least one of rolesToAdd or rolesToRemove")
    public boolean hasOperations() {
        return (rolesToAdd != null && !rolesToAdd.isEmpty()) ||
                (rolesToRemove != null && !rolesToRemove.isEmpty());
    }
}