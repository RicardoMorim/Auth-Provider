package com.ricardo.auth.domain.user.domainevents;

import com.ricardo.auth.domain.user.domainevents.enums.LoggedOutReason;

public record UserLoggedOutEvent(String username, String email, LoggedOutReason reason) {
}
