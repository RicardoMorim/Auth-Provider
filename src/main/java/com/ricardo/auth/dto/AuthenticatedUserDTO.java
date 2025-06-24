package com.ricardo.auth.dto;

import com.ricardo.auth.core.AuthenticatedUser;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * The type Authenticated user dto.
 */
public class AuthenticatedUserDTO implements AuthenticatedUser {

    private final String name;
    private final List<String> roles;

    /**
     * Instantiates a new Authenticated user dto.
     *
     * @param name        the email
     * @param authorities the authorities
     */
    public AuthenticatedUserDTO(String name, Collection<? extends GrantedAuthority> authorities) {
        this.name = name;
        this.roles = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public List<String> getRoles() {
        return roles;
    }
}