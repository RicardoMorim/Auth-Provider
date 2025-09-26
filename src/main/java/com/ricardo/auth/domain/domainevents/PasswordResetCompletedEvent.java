package com.ricardo.auth.domain.domainevents;

/**
 * The type Password reset completed event.
 */
public record PasswordResetCompletedEvent(String username, String email) {
}
