package com.ricardo.auth.controller;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.RefreshTokenService;
import com.ricardo.auth.core.TokenBlocklist;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import com.ricardo.auth.domain.refreshtoken.RefreshToken;
import com.ricardo.auth.domain.user.User;
import com.ricardo.auth.dto.AuthenticatedUserDTO;
import com.ricardo.auth.dto.ErrorResponse;
import com.ricardo.auth.dto.LoginRequestDTO;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Collection;
import java.util.Map;

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
    private final TokenBlocklist blocklist;

    private final Logger logger = org.slf4j.LoggerFactory.getLogger(AuthController.class);

    /**
     * Constructor with optional refresh token service
     *
     * @param jwtService            the jwt service
     * @param authenticationManager the authentication manager
     * @param refreshTokenService   the refresh token service
     * @param authProperties        the auth properties
     * @param blocklist             the blocklist
     */
    public AuthController(
            JwtService jwtService,
            AuthenticationManager authenticationManager,
            RefreshTokenService<User, Long> refreshTokenService,
            AuthProperties authProperties, TokenBlocklist blocklist) {
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.refreshTokenService = refreshTokenService;
        this.authProperties = authProperties;
        this.blocklist = blocklist;
    }

    /**
     * Login response entity.
     *
     * @param request  the request
     * @param response the response
     * @return the response entity
     */
    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> login(@RequestBody LoginRequestDTO request, HttpServletResponse response) {
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

            AuthProperties.Cookies.AccessCookie accessCfg = authProperties.getCookies().getAccess();
            AuthProperties.Cookies.RefreshCookie refreshCfg = authProperties.getCookies().getRefresh();

            ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", accessToken)
                    .httpOnly(accessCfg.isHttpOnly())
                    .secure(accessCfg.isSecure())
                    .sameSite(accessCfg.getSameSite().getValue())
                    .path(accessCfg.getPath())
                    .maxAge(Duration.ofSeconds(authProperties.getJwt().getAccessTokenExpiration() / 1000))
                    .build();

            ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh_token", refreshToken.getToken())
                    .httpOnly(refreshCfg.isHttpOnly())
                    .secure(refreshCfg.isSecure())
                    .sameSite(refreshCfg.getSameSite().getValue())
                    .path(refreshCfg.getPath())
                    .maxAge(Duration.ofSeconds(authProperties.getJwt().getRefreshTokenExpiration() / 1000))
                    .build();

            response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
            response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

            return ResponseEntity.ok().build();
        } else {
            // Legacy behavior - single token
            String token = jwtService.generateAccessToken(
                    userDetails.getUsername(),
                    userDetails.getAuthorities()
            );

            AuthProperties.Cookies.AccessCookie accessCfg = authProperties.getCookies().getAccess();

            ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", token)
                    .httpOnly(accessCfg.isHttpOnly())
                    .secure(accessCfg.isSecure())
                    .sameSite(accessCfg.getSameSite().getValue())
                    .path(accessCfg.getPath())
                    .maxAge(Duration.ofSeconds(authProperties.getJwt().getAccessTokenExpiration() / 1000))
                    .build();

            response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
            return ResponseEntity.ok().build();
        }
    }

    /**
     * Refresh token response entity.
     *
     * @param refreshTokenCookie the refresh token cookie
     * @param response           the response
     * @return the response entity
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@CookieValue(value = "refresh_token", required = false) String refreshTokenCookie, HttpServletResponse response) {
        if (refreshTokenService == null) {
            return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                    .body("Refresh tokens are not enabled");
        }

        try {
            if (!StringUtils.hasText(refreshTokenCookie) || refreshTokenCookie.trim().length() < 10) {
                return ResponseEntity.badRequest()
                        .body(new ErrorResponse("Refresh token is required"));
            }

            if (blocklist.isRevoked(refreshTokenCookie)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("message", "Refresh token revoked"));
            }


            // Find and verify the refresh token
            RefreshToken refreshToken = refreshTokenService.findByToken(refreshTokenCookie);
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

            AuthProperties.Cookies.AccessCookie accessCfg = authProperties.getCookies().getAccess();
            AuthProperties.Cookies.RefreshCookie refreshCfg = authProperties.getCookies().getRefresh();

            ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", newAccessToken)
                    .httpOnly(accessCfg.isHttpOnly())
                    .secure(accessCfg.isSecure())
                    .sameSite(accessCfg.getSameSite().getValue())
                    .path(accessCfg.getPath())
                    .maxAge(Duration.ofSeconds(authProperties.getJwt().getAccessTokenExpiration() / 1000))
                    .build();

            ResponseCookie refreshTokenCookieResp = ResponseCookie.from("refresh_token", newRefreshToken)
                    .httpOnly(refreshCfg.isHttpOnly())
                    .secure(refreshCfg.isSecure())
                    .sameSite(refreshCfg.getSameSite().getValue())
                    .path(refreshCfg.getPath())
                    .maxAge(Duration.ofSeconds(authProperties.getJwt().getRefreshTokenExpiration() / 1000))
                    .build();

            response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
            response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookieResp.toString());

            // Retorne apenas os cookies, sem corpo
            return ResponseEntity.ok().build();

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
        String name = authentication.getName();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        AuthenticatedUserDTO userDto = new AuthenticatedUserDTO(name, authorities);
        return ResponseEntity.ok(userDto);
    }

    /**
     * Logout response entity.
     *
     * @param response the response
     * @return the response entity
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        // Clear cookies
        AuthProperties.Cookies.AccessCookie accessCfg = authProperties.getCookies().getAccess();
        AuthProperties.Cookies.RefreshCookie refreshCfg = authProperties.getCookies().getRefresh();

        ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", "")
                .httpOnly(accessCfg.isHttpOnly())
                .secure(accessCfg.isSecure())
                .sameSite(accessCfg.getSameSite().getValue())
                .path(accessCfg.getPath())
                .maxAge(0) // Expire immediately
                .build();

        ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh_token", "")
                .httpOnly(refreshCfg.isHttpOnly())
                .secure(refreshCfg.isSecure())
                .sameSite(refreshCfg.getSameSite().getValue())
                .path(refreshCfg.getPath())
                .maxAge(0) // Expire immediately
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        return ResponseEntity.ok().build();
    }

    /**
     * Revoke token response entity.
     *
     * @param token the token
     * @return the response entity
     */
    @PostMapping("/revoke")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> revokeToken(@RequestBody String token) {
        blocklist.revoke(token);
        return ResponseEntity.ok().body(Map.of("message", "Token revoked successfully"));
    }
}
