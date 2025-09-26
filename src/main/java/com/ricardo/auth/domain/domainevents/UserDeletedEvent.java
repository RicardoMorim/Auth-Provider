package com.ricardo.auth.domain.domainevents;

/**
 * The type User deleted event.
 */
public record UserDeletedEvent(String username, String email) {
}
