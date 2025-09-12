package com.ricardo.auth.dto;

import lombok.Data;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.Pattern;

/**
 * Request DTO for password reset completion.
 * 
 * @since 3.1.0
 */
@Data
public class PasswordResetCompleteRequest {

    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
    @Pattern(
        regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]+$",
        message = "Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character"
    )
    private String password;

    @NotBlank(message = "Password confirmation is required")
    private String confirmPassword;

    /**
     * Validates that password and confirmPassword match.
     */
    public boolean isPasswordConfirmed() {
        return password != null && password.equals(confirmPassword);
    }
}
