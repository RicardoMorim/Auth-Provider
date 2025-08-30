package com.ricardo.auth.domain.user.domainevents;

public record UserDeletedEvent (String username, String email) {
}
