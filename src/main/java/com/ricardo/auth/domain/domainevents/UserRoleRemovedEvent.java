package com.ricardo.auth.domain.domainevents;

import com.ricardo.auth.core.Role;

public record UserRoleRemovedEvent (String username, String email, Role roleName) {
}
