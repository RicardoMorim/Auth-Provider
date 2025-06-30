package com.ricardo.auth.core;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

/**
 * The interface Jwt service.
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 */
public interface JwtService {
    /**
     * Generate token string.
     *
     * @param subject     the subject
     * @param authorities the authorities
     * @return the string
     */
    String generateToken(String subject, Collection<? extends GrantedAuthority> authorities);

    /**
     * Extract subject string.
     *
     * @param token the token
     * @return the string
     */
    String extractSubject(String token);

    /**
     * Is token valid boolean.
     *
     * @param token the token
     * @return the boolean
     */
    boolean isTokenValid(String token);

    /**
     * Extract roles list.
     *
     * @param token the token
     * @return the list
     */
    List<String> extractRoles(String token);
}