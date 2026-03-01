package com.ricardo.auth.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
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
    private String password;

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
