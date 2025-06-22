package com.ricardo.auth.domain;

import jakarta.persistence.Embeddable;
import lombok.Getter;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.Serializable;
import java.util.Objects;

@Getter
@Embeddable
public class Password implements Serializable {

    private String hashed;

    // Private constructor to ensure immutability
    private Password(String hashed) {
        this.hashed = hashed;
    }

    protected Password() {
    }

    /**
     * Factory method para criar uma instância a partir de uma hash existente.
     *
     * @param hashedPassword A password já codificada.
     * @return Uma nova instância de Password.
     */
    public static Password fromHash(String hashedPassword) {
        if (hashedPassword == null || hashedPassword.isBlank()) {
            throw new IllegalArgumentException("Password hash cannot be null or blank");
        }
        return new Password(hashedPassword);
    }

    /**
     * Factory method.
     * Encodes the password using the provided PasswordEncoder.
     * Validates the password length and format before encoding.
     *
     * @param password        the raw password to be hashed
     * @param passwordEncoder the PasswordEncoder to use for hashing
     *
     * @return a new instance of Password with the hashed value
     */
    public static Password valueOf(String password, PasswordEncoder passwordEncoder) {
        if (password == null || password.isBlank()) {
            throw new IllegalArgumentException("Password hash cannot be null or blank");
        }

        if (password.length() > 60) {
            throw new IllegalArgumentException("Password hash cannot be longer than 60 characters");
        }

        if (password.length() < 6) {
            throw new IllegalArgumentException("Password hash must be at least 6 characters long");
        }

        String hashedPassword = passwordEncoder.encode(password);

        return new Password(hashedPassword);
    }

    public boolean matches(String rawPassword, PasswordEncoder passwordEncoder) {
        if (rawPassword == null || rawPassword.isBlank()) {
            throw new IllegalArgumentException("Raw password cannot be null or blank");
        }
        return passwordEncoder.matches(rawPassword, this.hashed);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Password)) return false;
        Password that = (Password) o;
        return Objects.equals(hashed, that.hashed);
    }

    @Override
    public int hashCode() {
        return Objects.hash(hashed);
    }
}
