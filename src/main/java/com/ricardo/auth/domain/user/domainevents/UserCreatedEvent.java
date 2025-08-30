package com.ricardo.auth.domain.user.domainevents;

import com.ricardo.auth.core.Role;

import java.util.Set;

public record UserCreatedEvent(String username, String email, Set<? extends Role> roleSet) {
}
