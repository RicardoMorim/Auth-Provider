package com.ricardo.auth.domain.domainevents;

public record PasswordResetCompletedEvent (String username, String email) {
}
