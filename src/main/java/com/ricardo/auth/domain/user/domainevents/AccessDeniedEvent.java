package com.ricardo.auth.domain.user.domainevents;

import com.ricardo.auth.domain.user.domainevents.enums.AccessDeniedReason;

public record AccessDeniedEvent (String username, String email, AccessDeniedReason reason) {
}
