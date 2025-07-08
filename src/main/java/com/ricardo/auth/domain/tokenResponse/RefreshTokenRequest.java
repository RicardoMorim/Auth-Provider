package com.ricardo.auth.domain.tokenResponse;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DTO for refresh token requests.
 * Used when clients want to refresh their access tokens using their refresh token.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RefreshTokenRequest {

    /**
     * The refresh token value obtained from the login response
     */
    @NotBlank(message = "Refresh token is required")
    @Size(min = 10, max = 500, message = "Invalid refresh token format")
    private String refreshToken;

    @Override
    public String toString() {
        return "RefreshTokenRequest{refreshToken='[PROTECTED]'}";
    }
}