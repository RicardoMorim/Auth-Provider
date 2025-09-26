package com.ricardo.auth.domain.domainevents;


/**
 * The type User logged out event.
 */
public record UserLoggedOutEvent(String username, String email) {
}
