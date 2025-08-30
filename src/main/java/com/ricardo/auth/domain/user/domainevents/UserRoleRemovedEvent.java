package com.ricardo.auth.domain.user.domainevents;

import com.ricardo.auth.core.Role;

public record UserRoleRemovedEvent (String username, String email, Role roleName) {
}
