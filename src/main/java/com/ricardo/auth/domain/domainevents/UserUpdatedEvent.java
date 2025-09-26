package com.ricardo.auth.domain.domainevents;

/**
 * The type User updated event.
 */
public record UserUpdatedEvent(String email, String username) {
}
