package com.ricardo.auth.domain.domainevents;


public record UserLoggedOutEvent(String username, String email) {
}
