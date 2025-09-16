package com.ricardo.auth.domain.domainevents;

import com.ricardo.auth.core.Role;

/**
 * The type User role removed event.
 */
public record UserRoleRemovedEvent (String username, String email, Role roleName) {
}
