package com.ricardo.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * The type Token response.
 */
@Getter
@AllArgsConstructor
public class TokenResponse {
    private String accessToken;
    private String refreshToken;
}
