package com.ricardo.auth.domain.domainevents;

public record UserDeletedEvent (String username, String email) {
}
