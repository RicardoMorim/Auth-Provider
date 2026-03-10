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
import com.ricardo.auth.dto.RevokeTokenRequest;
import com.ricardo.auth.helper.LogSanitizer;
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
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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
    private final ConcurrentHashMap<String, LoginAttemptState> loginAttempts = new ConcurrentHashMap<>();

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
        String normalizedEmail = normalizeEmail(request.getEmail());

        if (isLoginTemporarilyLocked(normalizedEmail)) {
            logger.warn("Login temporarily locked due to too many failed attempts");
            eventPublisher.publishEvent(new UserAuthenticationFailedEvent(
                LogSanitizer.sanitize(normalizedEmail),
                AuthenticationFailedReason.INVALID_CREDENTIALS
            ));
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(new ErrorResponse("Too many failed login attempts. Please try again later."));
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

            Object principal = authentication.getPrincipal();
            if (principal == null) {
                logger.warn("Authentication failed: no principal returned by authentication provider");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(new ErrorResponse("Authentication failed: no principal"));
            }

            @SuppressWarnings("unchecked")
            U userDetails = (U) principal;

            clearFailedLoginAttempts(normalizedEmail);
            logger.info("Successful login");

            eventPublisher.publishEvent(new UserAuthenticatedEvent(
                    LogSanitizer.sanitize(userDetails.getUsername()),
                    LogSanitizer.sanitize(userDetails.getEmail()),
                    userDetails.getRoles()
            ));

            String accessToken = jwtService.generateAccessToken(
                    userDetails.getEmail(),
                    userDetails.getAuthorities()
            );

            if (refreshTokenService != null) {
                RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails);
                String cookieRefreshToken = refreshToken.getRawToken() != null ? refreshToken.getRawToken() : refreshToken.getToken();
                setAuthCookies(response, accessToken, cookieRefreshToken);
            } else {
                setAccessCookie(response, accessToken);
            }

            return ResponseEntity.ok().build();

        } catch (AuthenticationException e) {
            boolean lockedNow = recordFailedLoginAttempt(normalizedEmail);
            logger.warn("Failed login attempt");
            if (lockedNow) {
                logger.warn("Login temporarily locked due to repeated failed attempts");
            }

            eventPublisher.publishEvent(new UserAuthenticationFailedEvent(
                    LogSanitizer.sanitize(normalizedEmail),
                    AuthenticationFailedReason.INVALID_CREDENTIALS
            ));

                if (lockedNow) {
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(new ErrorResponse("Too many failed login attempts. Please try again later."));
                }

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

            String newRefreshToken = refreshTokenCookie;
            if (shouldRotateRefreshToken()) {
                RefreshToken newRefreshTokenObj = refreshTokenService.createRefreshToken(user);
                refreshTokenService.revokeToken(refreshTokenCookie);
                newRefreshToken = newRefreshTokenObj.getRawToken() != null
                    ? newRefreshTokenObj.getRawToken()
                    : newRefreshTokenObj.getToken();
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

        String email = null;
        if (StringUtils.hasText(accessToken)) {
            try {
                if (jwtService.isTokenValid(accessToken)) {
                    email = jwtService.extractSubject(accessToken);
                    blocklist.revoke(accessToken);
                    logger.debug("Access token revoked during logout");
                }
            } catch (Exception e) {
                logger.debug("Failed to validate/revoke access token during logout", e);
            }
        }


        logger.info("Processing logout request");

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
                logger.warn("Could not resolve user during logout");
            }
        }

        clearAuthCookies(response);
        if (user != null) {
            eventPublisher.publishEvent(new UserLoggedOutEvent(
                    LogSanitizer.sanitize(user.getUsername()),
                    LogSanitizer.sanitize(user.getEmail())
            ));
        }
        return ResponseEntity.ok().build();
    }

    /**
     * Admin endpoint to revoke any token
     *
     * @param request the revoke token request
     * @return the response entity
     */
    @PostMapping("/revoke")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> revokeToken(@Valid @RequestBody RevokeTokenRequest request) {
        String token = request.getToken().trim();

        // Basic JWT format validation (header.payload.signature)
        String[] parts = token.split("\\.");
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse("Invalid token format"));
        }

        blocklist.revoke(token);
        return ResponseEntity.ok().body(Map.of("message", "Token revoked successfully"));
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {

        PublicKey key = jwtService.getPublicKey();

        if (!(key instanceof RSAPublicKey rsaKey)) {
            throw new IllegalStateException("Public key is not an RSA key");
        }

        String kid = authProperties.getJwt().getKid();
        if (kid == null || kid.isBlank()) {
            kid = generateKeyId(rsaKey);
        }

        Map<String, Object> jwk = Map.of(
                "kty", "RSA",
                "alg", "RS256",
                "use", "sig",
                "kid", kid,
                "n", base64url(rsaKey.getModulus().toByteArray()),
                "e", base64url(rsaKey.getPublicExponent().toByteArray())
        );

        return Map.of("keys", List.of(jwk));
    }

    /**
     * Generate a key ID from the public key using SHA-256 hash.
     */
    private String generateKeyId(RSAPublicKey publicKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(publicKey.getEncoded());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            logger.warn("Failed to generate key ID from public key, using fallback", e);
            return "ricardo-auth-key-1";
        }
    }

    /**
     * Encode bytes to Base64url (no padding) as required by JWK spec.
     */
    private String base64url(byte[] bytes) {
        // RSA BigInteger may have a leading zero byte for sign - strip it
        if (bytes.length > 0 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            bytes = trimmed;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }


    private void setAuthCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        setAccessCookie(response, accessToken);
        setRefreshCookie(response, refreshToken);
    }

    private void setAccessCookie(HttpServletResponse response, String accessToken) {
        AuthProperties.Cookies.AccessCookie accessCfg = authProperties.getCookies().getAccess();

        ResponseCookie.ResponseCookieBuilder accessCookieBuilder = ResponseCookie.from("access_token", accessToken)
                .httpOnly(accessCfg.isHttpOnly())
                .secure(accessCfg.isSecure())
                .sameSite(accessCfg.getSameSite().getValue())
                .path(accessCfg.getPath())
                .maxAge(Duration.ofSeconds(authProperties.getJwt().getAccessTokenExpiration() / 1000));

        if (StringUtils.hasText(accessCfg.getDomain())) {
            accessCookieBuilder.domain(accessCfg.getDomain().trim());
        }

        ResponseCookie accessTokenCookie = accessCookieBuilder.build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
    }

    private void setRefreshCookie(HttpServletResponse response, String refreshToken) {
        AuthProperties.Cookies.RefreshCookie refreshCfg = authProperties.getCookies().getRefresh();

        ResponseCookie.ResponseCookieBuilder refreshCookieBuilder = ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(refreshCfg.isHttpOnly())
                .secure(refreshCfg.isSecure())
                .sameSite(refreshCfg.getSameSite().getValue())
                .path(refreshCfg.getPath())
                .maxAge(Duration.ofSeconds(authProperties.getJwt().getRefreshTokenExpiration() / 1000));

        if (StringUtils.hasText(refreshCfg.getDomain())) {
            refreshCookieBuilder.domain(refreshCfg.getDomain().trim());
        }

        ResponseCookie refreshTokenCookie = refreshCookieBuilder.build();

        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
    }

    private void clearAuthCookies(HttpServletResponse response) {
        AuthProperties.Cookies.AccessCookie accessCfg = authProperties.getCookies().getAccess();
        AuthProperties.Cookies.RefreshCookie refreshCfg = authProperties.getCookies().getRefresh();

        ResponseCookie.ResponseCookieBuilder accessCookieBuilder = ResponseCookie.from("access_token", "")
                .httpOnly(accessCfg.isHttpOnly())
                .secure(accessCfg.isSecure())
                .sameSite(accessCfg.getSameSite().getValue())
                .path(accessCfg.getPath())
            .maxAge(0);

        if (StringUtils.hasText(accessCfg.getDomain())) {
            accessCookieBuilder.domain(accessCfg.getDomain().trim());
        }

        ResponseCookie accessTokenCookie = accessCookieBuilder.build();

        ResponseCookie.ResponseCookieBuilder refreshCookieBuilder = ResponseCookie.from("refresh_token", "")
                .httpOnly(refreshCfg.isHttpOnly())
                .secure(refreshCfg.isSecure())
                .sameSite(refreshCfg.getSameSite().getValue())
                .path(refreshCfg.getPath())
            .maxAge(0);

        if (StringUtils.hasText(refreshCfg.getDomain())) {
            refreshCookieBuilder.domain(refreshCfg.getDomain().trim());
        }

        ResponseCookie refreshTokenCookie = refreshCookieBuilder.build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
    }

    private boolean shouldRotateRefreshToken() {
        if (authProperties != null && authProperties.getRefreshTokens() != null) {
            return authProperties.getRefreshTokens().isRotateOnRefresh();
        }
        return true;
    }

    private String normalizeEmail(String email) {
        if (!StringUtils.hasText(email)) {
            return "unknown";
        }
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private boolean isLoginTemporarilyLocked(String normalizedEmail) {
        AuthProperties.LoginLockout lockoutConfig = authProperties.getLoginLockout();
        if (lockoutConfig == null || !lockoutConfig.isEnabled()) {
            return false;
        }

        LoginAttemptState state = loginAttempts.get(normalizedEmail);
        if (state == null) {
            return false;
        }

        long now = Instant.now().toEpochMilli();
        if (state.lockUntilEpochMs > now) {
            return true;
        }

        if (state.lockUntilEpochMs > 0 && state.lockUntilEpochMs <= now) {
            loginAttempts.remove(normalizedEmail);
        }

        return false;
    }

    private boolean recordFailedLoginAttempt(String normalizedEmail) {
        AuthProperties.LoginLockout lockoutConfig = authProperties.getLoginLockout();
        if (lockoutConfig == null || !lockoutConfig.isEnabled()) {
            return false;
        }

        long now = Instant.now().toEpochMilli();
        LoginAttemptState state = loginAttempts.compute(normalizedEmail, (key, current) -> {
            if (current == null || now - current.windowStartEpochMs > lockoutConfig.getAttemptWindowMs()) {
                LoginAttemptState refreshed = new LoginAttemptState();
                refreshed.windowStartEpochMs = now;
                refreshed.failedAttempts = 1;
                return refreshed;
            }

            if (current.lockUntilEpochMs > now) {
                return current;
            }

            current.failedAttempts++;
            if (current.failedAttempts >= lockoutConfig.getMaxFailedAttempts()) {
                current.lockUntilEpochMs = now + lockoutConfig.getLockDurationMs();
            }
            return current;
        });

        return state != null && state.lockUntilEpochMs > now;
    }

    private void clearFailedLoginAttempts(String normalizedEmail) {
        if (normalizedEmail != null) {
            loginAttempts.remove(normalizedEmail);
        }
    }

    private static class LoginAttemptState {
        private int failedAttempts;
        private long windowStartEpochMs;
        private long lockUntilEpochMs;
    }
}
