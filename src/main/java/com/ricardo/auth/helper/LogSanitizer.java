package com.ricardo.auth.helper;

/**
 * Utility class for sanitizing strings before logging to prevent log injection attacks.
 */
public final class LogSanitizer {

    private static final int MAX_LOG_VALUE_LENGTH = 256;

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

        String trimmed = input.trim();
        StringBuilder safe = new StringBuilder(Math.min(trimmed.length(), MAX_LOG_VALUE_LENGTH));

        for (int index = 0; index < trimmed.length() && safe.length() < MAX_LOG_VALUE_LENGTH; index++) {
            char current = trimmed.charAt(index);
            if (Character.isISOControl(current)) {
                safe.append('_');
            } else {
                safe.append(current);
            }
        }

        if (trimmed.length() > MAX_LOG_VALUE_LENGTH) {
            safe.append("...");
        }

        return safe.toString();
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

