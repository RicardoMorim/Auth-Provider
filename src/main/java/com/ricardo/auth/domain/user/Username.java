package com.ricardo.auth.domain.user;

import jakarta.persistence.Embeddable;
import lombok.Getter;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Username value object with comprehensive security validations.
 * This class is the information expert for all username validation rules.
 */
@Embeddable
public class Username {
    private static final int MAX_LENGTH = 50;  // Increased for flexibility
    private static final int MIN_LENGTH = 3;

    // Enhanced regex pattern for security
    private static final Pattern VALID_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]+$");

    private static final Pattern PATH_TRAVERSAL_PATTERN = Pattern.compile(".*(\\.\\.[\\\\/]|[\\\\/]\\.\\.).*");

    // Reserved/system usernames that should not be allowed
    private static final List<String> RESERVED_USERNAMES = Arrays.asList(
        "admin", "administrator", "root", "system", "sys", "daemon", "service",
        "guest", "anonymous", "user", "test", "demo", "public", "null", "undefined",
        "api", "www", "ftp", "mail", "email", "support", "help", "info", "contact",
        "security", "auth", "login", "logout", "signin", "signup", "register"
    );

    // Error messages
    private static final String EMPTY_USERNAME_MESSAGE = "Username cannot be null or empty";
    private static final String LONG_USERNAME_MESSAGE = "Username cannot be longer than " + MAX_LENGTH + " characters";
    private static final String SHORT_USERNAME_MESSAGE = "Username must be at least " + MIN_LENGTH + " characters long";
    private static final String INVALID_CHARACTERS_MESSAGE = "Username can only contain letters, numbers, dots, underscores, and hyphens";
    private static final String RESERVED_USERNAME_MESSAGE = "Username is reserved and cannot be used";
    private static final String CONSECUTIVE_SPECIAL_MESSAGE = "Username cannot have consecutive special characters";
    private static final String START_END_SPECIAL_MESSAGE = "Username cannot start or end with special characters";

    @Getter
    private String username;

    private Username(String username) {
        validateAndNormalize(username);
    }

    /**
     * Instantiates a new Username.
     */
    protected Username() {
    }

    /**
     * Creates a Username instance with comprehensive validation.
     *
     * @param username the username string
     * @return the username VO
     * @throws IllegalArgumentException if username is invalid
     */
    public static Username valueOf(String username) {
        return new Username(username);
    }

    /**
     * Validates username format without creating an instance.
     * Useful for API validation before object creation.
     *
     * @param username the username to validate
     * @throws IllegalArgumentException if username is invalid
     */
    public static void validateFormat(String username) {
        new Username(username); // Will throw if invalid
    }

    /**
     * Checks if a username string would be valid.
     *
     * @param username the username to check
     * @return true if valid, false otherwise
     */
    public static boolean isValid(String username) {
        try {
            validateFormat(username);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private void validateAndNormalize(String username) {
        // Basic null/empty check
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException(EMPTY_USERNAME_MESSAGE);
        }

        // Normalize: trim and convert to lowercase for consistency
        String normalized = username.trim().toLowerCase();

        // Length validation
        if (normalized.length() > MAX_LENGTH) {
            throw new IllegalArgumentException(LONG_USERNAME_MESSAGE);
        }
        if (normalized.length() < MIN_LENGTH) {
            throw new IllegalArgumentException(SHORT_USERNAME_MESSAGE);
        }

        // Character validation
        if (!VALID_PATTERN.matcher(normalized).matches()) {
            throw new IllegalArgumentException(INVALID_CHARACTERS_MESSAGE);
        }

        // Security validations
        validateSecurity(normalized);

        // Business rule validations
        validateBusinessRules(normalized);

        this.username = normalized;
    }

    private void validateSecurity(String username) {
        // Check for reserved usernames
        if (RESERVED_USERNAMES.contains(username)) {
            throw new IllegalArgumentException(RESERVED_USERNAME_MESSAGE);
        }
    }

    private void validateBusinessRules(String username) {
        // Cannot start or end with special characters
        if (username.matches("^[._-].*") || username.matches(".*[._-]$")) {
            throw new IllegalArgumentException(START_END_SPECIAL_MESSAGE);
        }

        // Cannot have consecutive special characters
        if (username.matches(".*[._-]{2,}.*")) {
            throw new IllegalArgumentException(CONSECUTIVE_SPECIAL_MESSAGE);
        }

        // Cannot be all numbers (business rule to prevent confusion with IDs)
        if (username.matches("^\\d+$")) {
            throw new IllegalArgumentException("Username cannot be all numeric");
        }
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
