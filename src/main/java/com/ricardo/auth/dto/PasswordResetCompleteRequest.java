package com.ricardo.auth.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

/**
 * Request DTO for password reset completion.
 *
 */
@Data
@ToString(exclude = {"password", "confirmPassword"})
@AllArgsConstructor
@NoArgsConstructor
public class PasswordResetCompleteRequest {
    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]+$",
            message = "Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character"
    )
    private String password;

    @Size(min = 8, max = 128, message = "Confirm Password must be between 8 and 128 characters")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]+$",
            message = "Confirm Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character"
    )
    private String confirmPassword;

    /**
     * Validates that password and confirmPassword match.
     *
     * @return the boolean
     */
    @AssertTrue(message = "Password and confirmation do not match")
    @JsonIgnore
    public boolean isPasswordConfirmed() {
        return password != null && password.equals(confirmPassword);
    }

}
