package com.ricardo.auth.domain.user;

import jakarta.persistence.Embeddable;
import lombok.Getter;

/**
 * The type Username.
 */
@Embeddable
public class Username {
    private static final int MAX_LENGTH = 20;
    private static final int MIN_LENGTH = 3;
    private static final String REGEX = "^[a-zA-Z0-9._-]+$";
    private static final String EMPTY_USERNAME_MESSAGE = "Username cannot be null or empty";
    private static final String LONG_USERNAME_MESSAGE = "Username cannot be longer than 20 characters";
    private static final String SHORT_USERNAME_MESSAGE = "Username must be at least 3 characters long";
    private static final String INVALID_CHARACTERS_MESSAGE = "Username can only contain letters, numbers, dots, underscores, and hyphens";
    @Getter
    private String username;

    private Username(String username) {
        if (username == null || username.isEmpty()) {
            throw new IllegalArgumentException(EMPTY_USERNAME_MESSAGE);
        }
        if (username.length() > MAX_LENGTH) {
            throw new IllegalArgumentException(LONG_USERNAME_MESSAGE);
        }
        if (username.length() < MIN_LENGTH) {
            throw new IllegalArgumentException(SHORT_USERNAME_MESSAGE);
        }
        if (!username.matches(REGEX)) {
            throw new IllegalArgumentException(INVALID_CHARACTERS_MESSAGE);
        }
        this.username = username;
    }

    /**
     * Instantiates a new Username.
     */
    protected Username() {

    }

    /**
     * Value of username.
     *
     * @param username the username
     * @return the username
     */
    public static Username valueOf(String username) {
        return new Username(username);
    }

    @Override
    public String toString() {
        return username;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Username)) return false;
        Username that = (Username) o;
        return username.equals(that.username);
    }

    @Override
    public int hashCode() {
        return username.hashCode();
    }
}
