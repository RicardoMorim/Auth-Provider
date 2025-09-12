package com.ricardo.auth.dto;

import lombok.Data;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Request DTO for password reset initiation.
 * 
 * @since 3.1.0
 */
@Data
public class PasswordResetRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;
}
