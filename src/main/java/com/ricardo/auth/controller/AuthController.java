package com.ricardo.auth.controller;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.*;
import com.ricardo.auth.domain.domainevents.UserAuthenticatedEvent;
import com.ricardo.auth.domain.domainevents.UserAuthenticationFailedEvent;
import com.ricardo.auth.domain.domainevents.UserLoggedOutEvent;
import com.ricardo.auth.domain.domainevents.enums.AuthenticationFailedReason;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import com.ricardo.auth.domain.refreshtoken.RefreshToken;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.dto.AuthenticatedUserDTO;
import com.ricardo.auth.dto.ErrorResponse;
import com.ricardo.auth.dto.LoginRequestDTO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Collection;
import java.util.Map;

/**
 * Generic Auth Controller that works with any AuthUser implementation and ID type.
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 *
 * @param <U>  the user type that extends AuthUser
 * @param <R>  the type parameter
 * @param <ID> the ID type for the user
 */
@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "JWT Authentication endpoints")
public class AuthController<U extends AuthUser<ID, R>, R extends Role, ID> {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService<U, R, ID> refreshTokenService;
    private final AuthProperties authProperties;
    private final TokenBlocklist blocklist;
    private final UserService<U, R, ID> userService;
    private final Publisher eventPublisher;

    /**
     * Constructor with optional refresh token service
     *
     * @param jwtService            the jwt service
     * @param authenticationManager the authentication manager
     * @param refreshTokenService   the refresh token service (can be null)
     * @param authProperties        the auth properties
     * @param blocklist             the blocklist
     * @param eventPublisher        the event publisher
     * @param userService           the user service
     */
    public AuthController(
            JwtService jwtService,
            AuthenticationManager authenticationManager,
            RefreshTokenService<U, R, ID> refreshTokenService,
            AuthProperties authProperties,
            TokenBlocklist blocklist,
            Publisher eventPublisher, UserService<U, R, ID> userService) {
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.refreshTokenService = refreshTokenService;
        this.authProperties = authProperties;
        this.blocklist = blocklist;
        this.eventPublisher = eventPublisher;
        this.userService = userService;
    }

    private static String sanitizeForLogging(String input) {
        if (input == null) {
            return "null";
        }
        return input
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
                .replace("\"", "\\\"")
                .trim();
    }

    /**
     * Login endpoint that works with any AuthUser implementation
     *
     * @param request  the login request
     * @param response the HTTP response
     * @return the response entity
     */
    @Operation(
            summary = "User login",
            description = "Authenticate user with email and password, returns JWT tokens as HTTP-only cookies"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Authentication successful",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid credentials",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid request format",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)
                    )
            )
    })
    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    @Transactional
    public ResponseEntity<?> login(
            @Parameter(description = "Login credentials", required = true)
            @Valid @RequestBody LoginRequestDTO request,
            HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

            Object principal = authentication.getPrincipal();
            if (principal == null) {
                logger.warn("Authentication failed: no principal for email: {}", sanitizeForLogging(request.getEmail()));
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(new ErrorResponse("Authentication failed: no principal"));
            }

            @SuppressWarnings("unchecked")
            U userDetails = (U) principal;

            logger.info("Successful login for user: {}", sanitizeForLogging(userDetails.getEmail()));

            eventPublisher.publishEvent(new UserAuthenticatedEvent(
                    sanitizeForLogging(userDetails.getUsername()),
                    sanitizeForLogging(userDetails.getEmail()),
                    userDetails.getRoles()
            ));

            String accessToken = jwtService.generateAccessToken(
                    userDetails.getEmail(),
                    userDetails.getAuthorities()
            );

            if (refreshTokenService != null) {
                RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails);
                setAuthCookies(response, accessToken, refreshToken.getToken());
            } else {
                setAccessCookie(response, accessToken);
            }

            return ResponseEntity.ok().build();

        } catch (Exception e) {
            logger.warn("Failed login attempt for email: {} - {}",
                    sanitizeForLogging(request.getEmail()),
                    sanitizeForLogging(e.getMessage()));

            eventPublisher.publishEvent(new UserAuthenticationFailedEvent(
                    sanitizeForLogging(request.getEmail()),
                    AuthenticationFailedReason.INVALID_CREDENTIALS
            ));

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Authentication failed"));
        }
    }

    /**
     * Refresh token endpoint
     *
     * @param refreshTokenCookie the refresh token cookie
     * @param response           the HTTP response
     * @return the response entity
     */
    @Operation(
            summary = "Refresh JWT token",
            description = "Generate new access token using refresh token from HTTP-only cookie"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Token refreshed successfully",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid or expired refresh token",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "501",
                    description = "Refresh tokens not enabled",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)
                    )
            )
    })
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(
            @Parameter(description = "Refresh token from HTTP-only cookie", hidden = true)
            @CookieValue(value = "refresh_token", required = false) String refreshTokenCookie,
            HttpServletResponse response) {

        if (refreshTokenService == null) {
            return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                    .body(new ErrorResponse("Refresh tokens are not enabled"));
        }

        try {
            if (!StringUtils.hasText(refreshTokenCookie) || refreshTokenCookie.trim().length() < 10) {
                return ResponseEntity.badRequest()
                        .body(new ErrorResponse("Authentication failed"));
            }

            if (blocklist.isRevoked(refreshTokenCookie)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ErrorResponse("Authentication failed"));
            }

            RefreshToken refreshToken = refreshTokenService.findByToken(refreshTokenCookie);
            refreshToken = refreshTokenService.verifyExpiration(refreshToken);

            U user = refreshTokenService.getUserFromRefreshToken(refreshToken);

            String newAccessToken = jwtService.generateAccessToken(
                    user.getEmail(),
                    user.getAuthorities()
            );

            String newRefreshToken = refreshToken.getToken();
            if (shouldRotateRefreshToken()) {
                RefreshToken newRefreshTokenObj = refreshTokenService.createRefreshToken(user);
                refreshTokenService.revokeToken(refreshToken.getToken());
                newRefreshToken = newRefreshTokenObj.getToken();
                blocklist.revoke(refreshTokenCookie);
            }

            setAuthCookies(response, newAccessToken, newRefreshToken);
            return ResponseEntity.ok().build();

        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Authentication failed"));
        } catch (Exception e) {
            logger.error("Error refreshing token", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("An error occurred during authentication"));
        }
    }

    /**
     * Get authenticated user information
     *
     * @param authentication the authentication
     * @return the authenticated user DTO
     */
    @Operation(
            summary = "Get current user info",
            description = "Get information about the currently authenticated user",
            security = @SecurityRequirement(name = "CookieAuth")
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "User information retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = AuthenticatedUserDTO.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Not authenticated",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)
                    )
            )
    })
    @GetMapping("/me")
    public ResponseEntity<AuthenticatedUserDTO> getAuthenticatedUser(
            @Parameter(hidden = true) Authentication authentication) {
        String name = authentication.getName();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        AuthenticatedUserDTO userDto = new AuthenticatedUserDTO(name, authorities);
        return ResponseEntity.ok(userDto);
    }

    /**
     * Logout endpoint with token revocation
     *
     * @param response     the HTTP response
     * @param accessToken  the access token from cookie (optional)
     * @param refreshToken the refresh token from cookie (optional)
     * @return the response entity
     */
    @Operation(
            summary = "User logout",
            description = "Logout user by revoking tokens and clearing HTTP-only cookies"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Logout successful",
                    content = @Content(mediaType = "application/json")
            )
    })
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            HttpServletResponse response,
            @Parameter(description = "Access token from HTTP-only cookie", hidden = true)
            @CookieValue(value = "access_token", required = false) String accessToken,
            @Parameter(description = "Refresh token from HTTP-only cookie", hidden = true)
            @CookieValue(value = "refresh_token", required = false) String refreshToken) {

        if (StringUtils.hasText(accessToken)) {
            try {
                if (jwtService.isTokenValid(accessToken)) {
                    blocklist.revoke(accessToken);
                    logger.debug("Access token revoked during logout");
                }
            } catch (Exception e) {
                logger.debug("Failed to validate/revoke access token during logout", e);
            }
        }

        String email = jwtService.extractSubject(accessToken);

        if (email == null) {
            logger.info("Logging out user with unknown email");
        } else {
            logger.info("Logging out user: {}", sanitizeForLogging(email));
        }

        if (StringUtils.hasText(refreshToken) && refreshTokenService != null) {
            try {
                blocklist.revoke(refreshToken);
                refreshTokenService.revokeToken(refreshToken);
                logger.debug("Refresh token revoked during logout");
            } catch (Exception e) {
                logger.debug("Failed to revoke refresh token during logout", e);
            }
        }

        U user = null;
        if (email != null) {
            try {
                user = userService.getUserByEmail(email);
            } catch (Exception e) {
                logger.warn("Could not find user during logout for email: {}", sanitizeForLogging(email));
            }
        }

        clearAuthCookies(response);
        if (user != null) {
            eventPublisher.publishEvent(new UserLoggedOutEvent(
                    sanitizeForLogging(user.getUsername()),
                    sanitizeForLogging(user.getEmail())
            ));
        }
        return ResponseEntity.ok().build();
    }

    /**
     * Admin endpoint to revoke any token
     *
     * @param token the token to revoke
     * @return the response entity
     */
    @PostMapping("/revoke")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> revokeToken(@RequestBody String token) {
        // Sanitize only if used in logs — not used here, but safe to sanitize if logged later
        blocklist.revoke(token);
        return ResponseEntity.ok().body(Map.of("message", "Token revoked successfully"));
    }

    private void setAuthCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        setAccessCookie(response, accessToken);
        setRefreshCookie(response, refreshToken);
    }

    private void setAccessCookie(HttpServletResponse response, String accessToken) {
        AuthProperties.Cookies.AccessCookie accessCfg = authProperties.getCookies().getAccess();

        ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", accessToken)
                .httpOnly(accessCfg.isHttpOnly())
                .secure(accessCfg.isSecure())
                .sameSite(accessCfg.getSameSite().getValue())
                .path(accessCfg.getPath())
                .maxAge(Duration.ofSeconds(authProperties.getJwt().getAccessTokenExpiration() / 1000))
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
    }

    private void setRefreshCookie(HttpServletResponse response, String refreshToken) {
        AuthProperties.Cookies.RefreshCookie refreshCfg = authProperties.getCookies().getRefresh();

        ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(refreshCfg.isHttpOnly())
                .secure(refreshCfg.isSecure())
                .sameSite(refreshCfg.getSameSite().getValue())
                .path(refreshCfg.getPath())
                .maxAge(Duration.ofSeconds(authProperties.getJwt().getRefreshTokenExpiration() / 1000))
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
    }

    private void clearAuthCookies(HttpServletResponse response) {
        AuthProperties.Cookies.AccessCookie accessCfg = authProperties.getCookies().getAccess();
        AuthProperties.Cookies.RefreshCookie refreshCfg = authProperties.getCookies().getRefresh();

        ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", "")
                .httpOnly(accessCfg.isHttpOnly())
                .secure(accessCfg.isSecure())
                .sameSite(accessCfg.getSameSite().getValue())
                .path(accessCfg.getPath())
                .maxAge(0)
                .build();

        ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh_token", "")
                .httpOnly(refreshCfg.isHttpOnly())
                .secure(refreshCfg.isSecure())
                .sameSite(refreshCfg.getSameSite().getValue())
                .path(refreshCfg.getPath())
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
    }

    private boolean shouldRotateRefreshToken() {
        if (authProperties != null && authProperties.getRefreshTokens() != null) {
            return authProperties.getRefreshTokens().isRotateOnRefresh();
        }
        return true;
    }
}