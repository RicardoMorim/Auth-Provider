package com.ricardo.auth.dto;

/**
 * The type Token dto.
 */
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
