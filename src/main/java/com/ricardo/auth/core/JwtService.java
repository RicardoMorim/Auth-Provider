package com.ricardo.auth.core;

import org.springframework.security.core.GrantedAuthority;
import java.util.Collection;
import java.util.List;

public interface JwtService {
    String generateToken(String subject, Collection<? extends GrantedAuthority> authorities);
    String extractSubject(String token);
    boolean isTokenValid(String token);
    List<String> extractRoles(String token);
}