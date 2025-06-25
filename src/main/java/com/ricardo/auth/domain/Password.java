package com.ricardo.auth.domain;

import com.ricardo.auth.core.PasswordPolicyService;
import jakarta.persistence.Embeddable;
import lombok.Getter;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.Serializable;
import java.util.Objects;

/**
 * The type Password.
 */
@Getter
@Embeddable
public class Password implements Serializable {

    private String hashed;

    // Private constructor to ensure immutability
    private Password(String hashed) {
        this.hashed = hashed;
    }

    /**
     * Instantiates a new Password.
     */
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
     * @return a new instance of Password with the hashed value
     */
    public static Password valueOf(String password, PasswordEncoder passwordEncoder, PasswordPolicyService passwordPolicyService) {
        if (!passwordPolicyService.validatePassword(password)) {
            throw new IllegalArgumentException("Password does not meet the required policy");
        }

        String hashedPassword = passwordEncoder.encode(password);

        return new Password(hashedPassword);
    }

    /**
     * Matches boolean.
     *
     * @param rawPassword     the raw password
     * @param passwordEncoder the password encoder
     * @return the boolean
     */
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
