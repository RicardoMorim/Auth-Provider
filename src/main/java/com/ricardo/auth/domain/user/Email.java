package com.ricardo.auth.domain.user;

import jakarta.persistence.Embeddable;

import java.io.Serializable;

/**
 * The type Email.
 */
@Embeddable
public class Email implements Serializable {

    private String email;

    private Email(String email) {
        this.email = email;
    }

    /**
     * Instantiates a new Email.
     */
    protected Email() {
    }

    /**
     * Gets email.
     *
     * @return the email
     */
    public String getEmail() {
        return email;
    }

    @Override
    public String toString() {
        return email;
    }

    /**
     * Value of email.
     *
     * @param email the email
     * @return the email
     */
    public static Email valueOf(String email) {
        if (email == null || email.isEmpty()) {
            throw new IllegalArgumentException("Email cannot be null or empty");
        }

        if (!email.contains("@") || !email.contains(".")) {
            throw new IllegalArgumentException("Invalid email format");
        }

        email = email.trim().toLowerCase(); // Normalize email
        if (email.length() > 254) {
            throw new IllegalArgumentException("Email cannot be longer than 254 characters");
        }
        if (!email.matches("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$")) {
            throw new IllegalArgumentException("Email does not match the required format");
        }

        return new Email(email);
    }
}
