package com.ricardo.auth.domain.domainevents;

import com.ricardo.auth.core.Role;

public record UserRoleAddedEvent(String username, String email, Role role) {

}
