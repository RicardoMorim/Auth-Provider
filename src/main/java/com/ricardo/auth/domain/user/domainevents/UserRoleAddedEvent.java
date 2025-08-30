package com.ricardo.auth.domain.user.domainevents;

import com.ricardo.auth.core.Role;

public record UserRoleAddedEvent(String username, String email, Role role) {

}
