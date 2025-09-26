package com.ricardo.auth.domain.domainevents;

import com.ricardo.auth.core.Role;

import java.util.Set;

/**
 * The type User created event.
 */
public record UserCreatedEvent(String username, String email, Set<? extends Role> roleSet) {
}
