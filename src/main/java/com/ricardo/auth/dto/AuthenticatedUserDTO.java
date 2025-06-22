package com.ricardo.auth.dto;

import com.ricardo.auth.core.AuthenticatedUser;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class AuthenticatedUserDTO implements AuthenticatedUser {

    private final String email;
    private final List<String> roles;

    public AuthenticatedUserDTO(String email, Collection<? extends GrantedAuthority> authorities) {
        this.email = email;
        this.roles = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
    }

    @Override
    public String getEmail() {
        return email;
    }

    @Override
    public List<String> getRoles() {
        return roles;
    }
}