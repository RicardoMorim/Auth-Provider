package com.ricardo.auth.domain;

import com.ricardo.auth.domain.user.Email;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The type Email test.
 */
class EmailTest {

    /**
     * Should create valid email.
     */
    @Test
    void shouldCreateValidEmail() {
        assertDoesNotThrow(() -> Email.valueOf("test@example.com"));
    }

    /**
     * Should throw exception for null email.
     */
    @Test
    void shouldThrowExceptionForNullEmail() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            Email.valueOf(null);
        });
        assertEquals("Email cannot be null or empty", exception.getMessage());
    }

    /**
     * Should throw exception for invalid format.
     *
     * @param invalidEmail the invalid email
     */
    @ParameterizedTest
    @ValueSource(strings = {"", " ", "plainaddress", "test@.com", "@example.com"})
    void shouldThrowExceptionForInvalidFormat(String invalidEmail) {
        assertThrows(IllegalArgumentException.class, () -> {
            Email.valueOf(invalidEmail);
        });
    }
}