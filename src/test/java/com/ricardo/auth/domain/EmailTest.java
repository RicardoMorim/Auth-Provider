package com.ricardo.auth.domain;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

class EmailTest {

    @Test
    void shouldCreateValidEmail() {
        assertDoesNotThrow(() -> Email.valueOf("test@example.com"));
    }

    @Test
    void shouldThrowExceptionForNullEmail() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            Email.valueOf(null);
        });
        assertEquals("Email cannot be null or empty", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "plainaddress", "test@.com", "@example.com"})
    void shouldThrowExceptionForInvalidFormat(String invalidEmail) {
        assertThrows(IllegalArgumentException.class, () -> {
            Email.valueOf(invalidEmail);
        });
    }
}