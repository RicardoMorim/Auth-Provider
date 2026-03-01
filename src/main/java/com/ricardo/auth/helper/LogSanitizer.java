package com.ricardo.auth.helper;

/**
 * Utility class for sanitizing strings before logging to prevent log injection attacks.
 */
public final class LogSanitizer {

    private LogSanitizer() {
        // Utility class
    }

    /**
     * Sanitize a string for safe log output by escaping CR, LF, tab, and quote characters.
     *
     * @param input the input string
     * @return the sanitized string, or "null" if input is null
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        return input
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
                .replace("\"", "\\\"")
                .trim();
    }

    /**
     * Sanitize an object's toString() for safe log output.
     *
     * @param obj the object
     * @return the sanitized string, or "null" if object is null
     */
    public static String sanitizeId(Object obj) {
        if (obj == null) return "null";
        return sanitize(obj.toString());
    }
}

