package com.ricardo.auth.controller;

import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.dto.AuthenticatedUserDTO;
import com.ricardo.auth.dto.LoginRequestDTO;
import com.ricardo.auth.dto.TokenDTO;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;

/**
 * The type Auth controller.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    /**
     * Instantiates a new Auth controller.
     *
     * @param jwtService            the jwt service
     * @param authenticationManager the authentication manager
     */
    public AuthController(JwtService jwtService, AuthenticationManager authenticationManager) {
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    /**
     * Login response entity.
     *
     * @param request the request
     * @return the response entity
     */
    @PostMapping("/login")
    public ResponseEntity<TokenDTO> login(@RequestBody LoginRequestDTO request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String token = jwtService.generateToken(userDetails.getUsername(), userDetails.getAuthorities());

        return ResponseEntity.ok(new TokenDTO(token));
    }

    /**
     * Gets authenticated user.
     *
     * @param authentication the authentication
     * @return the authenticated user
     */
    @GetMapping("/me")
    public ResponseEntity<AuthenticatedUserDTO> getAuthenticatedUser(Authentication authentication) {
        String name;
        Collection<? extends GrantedAuthority> authorities;

        // Handle different authentication types
        if (authentication.getPrincipal() instanceof UserDetails) {
            // Session-based authentication (from login)
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            name = userDetails.getUsername();
            authorities = userDetails.getAuthorities();
        } else if (authentication.getPrincipal() instanceof String) {
            // JWT-based authentication
            name = (String) authentication.getPrincipal();
            authorities = authentication.getAuthorities();
        } else {
            throw new IllegalStateException("Unknown authentication principal type");
        }

        AuthenticatedUserDTO userDto = new AuthenticatedUserDTO(name, authorities);
        return ResponseEntity.ok(userDto);
    }
}
