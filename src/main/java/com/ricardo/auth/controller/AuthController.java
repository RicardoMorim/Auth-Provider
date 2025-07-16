package com.ricardo.auth.controller;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.RefreshTokenService;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import com.ricardo.auth.domain.tokenResponse.RefreshToken;
import com.ricardo.auth.domain.tokenResponse.RefreshTokenRequest;
import com.ricardo.auth.domain.user.User;
import com.ricardo.auth.dto.*;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.springframework.http.HttpStatus;
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
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService<User, Long> refreshTokenService;
    private final AuthProperties authProperties;

    private final Logger logger = org.slf4j.LoggerFactory.getLogger(AuthController.class);

    /**
     * Constructor with optional refresh token service
     *
     * @param jwtService            the jwt service
     * @param authenticationManager the authentication manager
     * @param refreshTokenService   the refresh token service
     * @param authProperties        the auth properties
     */
    public AuthController(
            JwtService jwtService,
            AuthenticationManager authenticationManager,
            RefreshTokenService<User, Long> refreshTokenService,
            AuthProperties authProperties) {
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.refreshTokenService = refreshTokenService;
        this.authProperties = authProperties;
    }

    /**
     * Login response entity.
     *
     * @param request the request
     * @return the response entity
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDTO request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        if (refreshTokenService != null) {
            // Generate both access and refresh tokens
            String accessToken = jwtService.generateAccessToken(
                    userDetails.getUsername(),
                    userDetails.getAuthorities()
            );

            User user = (User) userDetails; // Cast to your User implementation
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

            return ResponseEntity.ok(new TokenResponse(accessToken, refreshToken.getToken()));
        } else {
            // Legacy behavior - single token
            String token = jwtService.generateAccessToken(
                    userDetails.getUsername(),
                    userDetails.getAuthorities()
            );
            return ResponseEntity.ok(new TokenDTO(token));
        }
    }

    /**
     * Refresh token response entity.
     *
     * @param request the request
     * @return the response entity
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        if (refreshTokenService == null) {
            return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                    .body("Refresh tokens are not enabled");
        }

        try {
            if (request == null || request.getRefreshToken() == null || request.getRefreshToken().trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(new ErrorResponse("Refresh token is required"));
            }

            // Find and verify the refresh token
            RefreshToken refreshToken = refreshTokenService.findByToken(request.getRefreshToken());
            refreshToken = refreshTokenService.verifyExpiration(refreshToken);

            // Get the user from the refresh token
            User user = refreshTokenService.getUserFromRefreshToken(refreshToken);

            // Generate new access token
            String newAccessToken = jwtService.generateAccessToken(
                    user.getEmail(),
                    user.getAuthorities()
            );

            // Optional: Rotate refresh token (generate new one)
            String newRefreshToken = refreshToken.getToken(); // Keep same token
            if (shouldRotateRefreshToken()) {
                RefreshToken newRefreshTokenObj = refreshTokenService.createRefreshToken(user);
                refreshTokenService.revokeToken(refreshToken.getToken());
                newRefreshToken = newRefreshTokenObj.getToken();
            }

            return ResponseEntity.ok(new TokenResponse(newAccessToken, newRefreshToken));

        } catch (ResourceNotFoundException e) {
            // Token not found, expired, or revoked - this is an authentication failure
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Invalid or expired refresh token"));
        } catch (Exception e) {
            // Any other error - log it and return generic error
            logger.error("Error refreshing token", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("An error occurred while refreshing the token"));
        }
    }


    /**
     * Determines whether refresh tokens should be rotated on each use.
     * Checks the configuration property and provides a sensible default.
     *
     * @return true if refresh tokens should be rotated, false otherwise
     */
    private boolean shouldRotateRefreshToken() {
        if (authProperties != null && authProperties.getRefreshTokens() != null) {
            return authProperties.getRefreshTokens().isRotateOnRefresh();
        }

        // Default behavior when no configuration is available
        // You can choose the default based on your security preferences
        return true; // Default to rotating for better security
    }

    /**
     * Gets authenticated user.
     *
     * @param authentication the authentication
     * @return the authenticated user
     */
    @GetMapping("/me")
    public ResponseEntity<AuthenticatedUserDTO> getAuthenticatedUser(Authentication authentication) {
        // This method stays the same - works with any token type
        String name = authentication.getName();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        AuthenticatedUserDTO userDto = new AuthenticatedUserDTO(name, authorities);
        return ResponseEntity.ok(userDto);
    }
}
