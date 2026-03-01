package com.ricardo.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Request DTO for token revocation.
 */
@AllArgsConstructor
@Getter
@NoArgsConstructor
public class RevokeTokenRequest {

    @NotBlank(message = "Token is required")
    @Size(min = 10, max = 4096, message = "Invalid token format")
    private String token;
}

