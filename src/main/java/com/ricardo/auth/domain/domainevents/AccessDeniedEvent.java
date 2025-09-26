package com.ricardo.auth.domain.domainevents;

import com.ricardo.auth.domain.domainevents.enums.AccessDeniedReason;

/**
 * The type Access denied event.
 */
public record AccessDeniedEvent (String username, String email, AccessDeniedReason reason) {
}
