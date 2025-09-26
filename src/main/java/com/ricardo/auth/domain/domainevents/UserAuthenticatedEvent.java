package com.ricardo.auth.domain.domainevents;

import com.ricardo.auth.core.Role;

import java.util.Set;

/**
 * The type User authenticated event.
 */
public record UserAuthenticatedEvent(String username, String email, Set<? extends Role> roleSet) {
}
