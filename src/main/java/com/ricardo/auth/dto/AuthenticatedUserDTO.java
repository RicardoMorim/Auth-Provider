package com.ricardo.auth.dto;

import com.ricardo.auth.core.AuthenticatedUser;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * The type Authenticated user dto.
 */
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticatedUserDTO implements AuthenticatedUser {

    @NonNull
    @NotBlank
    private String email;
    private List<String> roles;

    /**
     * Instantiates a new Authenticated user dto.
     *
     * @param email       the email
     * @param authorities the authorities
     */
    public AuthenticatedUserDTO(String email, Collection<? extends GrantedAuthority> authorities) {
        this.email = java.util.Objects.requireNonNull(email, "email must not be null");

        if (email.isBlank()) {
            throw new IllegalArgumentException("Email cannot be blank");
        }

        final java.util.Collection<? extends GrantedAuthority> safeAuthorities =
                authorities != null ? authorities : java.util.Collections.emptyList();
        this.roles = java.util.Collections.unmodifiableList(
                safeAuthorities.stream()
                        .filter(java.util.Objects::nonNull)
                        .map(GrantedAuthority::getAuthority)
                        .filter(java.util.Objects::nonNull)
                        .distinct()
                        .collect(Collectors.toList())
        );
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