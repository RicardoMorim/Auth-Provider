package com.ricardo.auth.dto;

import lombok.NoArgsConstructor;

/**
 * The type Token dto.
 */
@NoArgsConstructor
public class TokenDTO {
    private String token;

    /**
     * Instantiates a new Token dto.
     *
     * @param token the token
     */
    public TokenDTO(String token) {
        this.token = token;
    }

    /**
     * Gets token.
     *
     * @return the token
     */
    public String getToken() {
        return token;
    }
}
