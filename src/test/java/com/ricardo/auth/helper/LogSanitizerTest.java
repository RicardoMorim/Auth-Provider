package com.ricardo.auth.helper;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LogSanitizerTest {

    @Test
    void sanitize_shouldReturnNullLiteral_whenInputIsNull() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_shouldTrimAndReplaceControlCharacters() {
        String input = "  abc\n\tdef\r  ";

        String result = LogSanitizer.sanitize(input);

        assertEquals("abc__def", result);
    }

    @Test
    void sanitize_shouldTruncateAndAppendEllipsis_whenInputExceedsMaxLength() {
        String input = "a".repeat(260);

        String result = LogSanitizer.sanitize(input);

        assertEquals(259, result.length());
        assertEquals("a".repeat(256) + "...", result);
    }

    @Test
    void sanitizeId_shouldReturnNullLiteral_whenObjectIsNull() {
        assertEquals("null", LogSanitizer.sanitizeId(null));
    }

    @Test
    void sanitizeId_shouldSanitizeObjectToString() {
        Object value = new Object() {
            @Override
            public String toString() {
                return "  id\n123  ";
            }
        };

        assertEquals("id_123", LogSanitizer.sanitizeId(value));
    }
}
