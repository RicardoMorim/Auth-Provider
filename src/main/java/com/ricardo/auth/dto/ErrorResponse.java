package com.ricardo.auth.dto;

/**
 * The type Error response.
 */
public class ErrorResponse {
    private String message;

    /**
     * Instantiates a new Error response.
     *
     * @param message the message
     */
    public ErrorResponse(String message) {
        this.message = message;
    }

    /**
     * Gets message.
     *
     * @return the message
     */
    public String getMessage() {
        return message;
    }
}
