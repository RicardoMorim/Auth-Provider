package com.ricardo.auth.controller;

import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.dto.AuthenticatedUserDTO;
import com.ricardo.auth.dto.LoginRequestDTO;
import com.ricardo.auth.dto.TokenDTO;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthController(JwtService jwtService, AuthenticationManager authenticationManager) {
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/login")
    public ResponseEntity<TokenDTO> login(@RequestBody LoginRequestDTO request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String token = jwtService.generateToken(userDetails.getUsername(), userDetails.getAuthorities());

        return ResponseEntity.ok(new TokenDTO(token));
    }

    @GetMapping("/me")
    public ResponseEntity<AuthenticatedUserDTO> getAuthenticatedUser(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        AuthenticatedUserDTO userDto = new AuthenticatedUserDTO(
                userDetails.getUsername(),
                userDetails.getAuthorities()
        );
        return ResponseEntity.ok(userDto);
    }
}
