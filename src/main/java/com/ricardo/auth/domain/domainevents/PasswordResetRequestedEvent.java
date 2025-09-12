package com.ricardo.auth.domain.domainevents;

public record PasswordResetRequestedEvent (String username, String email){
}
