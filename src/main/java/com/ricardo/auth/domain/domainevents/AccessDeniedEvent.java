package com.ricardo.auth.domain.domainevents;

import com.ricardo.auth.domain.domainevents.enums.AccessDeniedReason;

public record AccessDeniedEvent (String username, String email, AccessDeniedReason reason) {
}
