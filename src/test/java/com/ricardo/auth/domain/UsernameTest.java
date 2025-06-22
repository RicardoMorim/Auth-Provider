package com.ricardo.auth.domain;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The type Username test.
 */
class UsernameTest {

    /**
     * Should create valid username.
     */
    @Test
    void shouldCreateValidUsername() {
        assertDoesNotThrow(() -> Username.valueOf("valid.user-123"));
    }

    /**
     * Should throw exception for short username.
     */
    @Test
    void shouldThrowExceptionForShortUsername() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            Username.valueOf("ab");
        });
        assertEquals("Username must be at least 3 characters long", exception.getMessage());
    }

    /**
     * Should throw exception for invalid characters.
     */
    @Test
    void shouldThrowExceptionForInvalidCharacters() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            Username.valueOf("invalid user!");
        });
        assertEquals("Username can only contain letters, numbers, dots, underscores, and hyphens", exception.getMessage());
    }
}