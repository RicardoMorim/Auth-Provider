package com.ricardo.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * The type Login request dto.
 */
@AllArgsConstructor
@Getter
public class LoginRequestDTO {
    
    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Size(max = 255, message = "Email must be less than 255 characters")
    private String email;
    
    @NotBlank(message = "Password is required")
    @Size(min = 1, max = 500, message = "Password must be between 1 and 500 characters")
    private String password;
}

