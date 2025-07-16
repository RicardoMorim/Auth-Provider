package com.ricardo.auth.domain.exceptions;

/**
 * The type Token expired exception.
 */
public class TokenExpiredException extends RuntimeException {
    /**
     * Instantiates a new Token expired exception.
     */
    public TokenExpiredException() {
        super("Token has expired");
    }

    /**
     * Instantiates a new Token expired exception.
     *
     * @param message the message
     */
    public TokenExpiredException(String message) {
        super(message);
    }

    /**
     * Instantiates a new Token expired exception.
     *
     * @param message the message
     * @param cause   the cause
     */
    public TokenExpiredException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Instantiates a new Token expired exception.
     *
     * @param cause the cause
     */
    public TokenExpiredException(Throwable cause) {
        super(cause);
    }
}
