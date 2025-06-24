package com.ricardo.auth.domain.exceptions;

/**
 * The type Duplicate resource exception.
 */
public class DuplicateResourceException extends RuntimeException {
    /**
     * Instantiates a new Duplicate resource exception.
     *
     * @param message the message
     */
    public DuplicateResourceException(String message) {
        super(message);
    }
}