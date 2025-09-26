package com.ricardo.auth.domain.domainevents;

import com.ricardo.auth.core.Role;

/**
 * The type User role added event.
 */
public record UserRoleAddedEvent(String username, String email, Role role) {

}
