package com.ricardo.auth.controller;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.PasswordResetService;
import com.ricardo.auth.core.RateLimiter;
import com.ricardo.auth.domain.domainevents.TooManyAuthRequestsEvent;
import com.ricardo.auth.dto.PasswordResetCompleteRequest;
import com.ricardo.auth.dto.PasswordResetRequest;
import com.ricardo.auth.service.EventPublisher;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Password reset controller with rate limiting and security measures.
 */
@RestController
@RequestMapping("/api/auth")
@Validated
@Slf4j
@Tag(name = "Password Reset", description = "Secure password reset endpoints")
public class PasswordResetController {

    private final PasswordResetService passwordResetService;
    private final RateLimiter rateLimiter;
    private final EventPublisher eventPublisher;

    public PasswordResetController(PasswordResetService passwordResetService, @Qualifier("passwordResetRateLimiter") RateLimiter rateLimiter, EventPublisher eventPublisher, AuthProperties authProperties) {
        this.passwordResetService = passwordResetService;
        this.rateLimiter = rateLimiter;
        this.eventPublisher = eventPublisher;
    }

    /**
     * Request a password reset for the given email address.
     * Implements rate limiting and timing attack prevention.
     */
    @Operation(
        summary = "Request password reset",
        description = "Request a password reset email. Always returns success to prevent user enumeration."
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200", 
            description = "Request processed (always returns success)",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "429", 
            description = "Too many requests - rate limit exceeded",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid request format",
            content = @Content(mediaType = "application/json")
        )
    })
    @PostMapping("/reset-request")
    public ResponseEntity<Map<String, String>> requestPasswordReset(
            @Parameter(description = "Password reset request with email", required = true)
            @Valid @RequestBody PasswordResetRequest request,
            @Parameter(hidden = true) HttpServletRequest httpRequest) {

        String clientIp = getClientIp(httpRequest);
        String rateLimitKey = "password_reset:" + clientIp;

        // Apply rate limiting per IP using existing infrastructure
        if (rateLimiter.isEnabled() && !rateLimiter.allowRequest(rateLimitKey)) {
            log.warn("Rate limit exceeded for password reset request from IP: {}", clientIp);
            
            // Publish rate limit exceeded event (only email, no IP for privacy)
            eventPublisher.publishEvent(new TooManyAuthRequestsEvent(request.getEmail()));
            
            return ResponseEntity.status(429)
                    .body(Map.of("message", "Too many requests. Please try again later."));
        }

        try {
            passwordResetService.requestPasswordReset(request.getEmail());

            // Always return success message (prevent user enumeration)
            return ResponseEntity.ok(Map.of(
                    "message", "If an account with that email exists, you will receive password reset instructions."
            ));

        } catch (Exception e) {
            log.error("Error processing password reset request", e);

            // Don't expose internal errors
            return ResponseEntity.ok(Map.of(
                    "message", "If an account with that email exists, you will receive password reset instructions."
            ));
        }
    }

    /**
     * Complete password reset using a valid token.
     */
    @Operation(
        summary = "Complete password reset",
        description = "Complete password reset using a valid token and new password"
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200", 
            description = "Password reset completed successfully",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "400", 
            description = "Invalid token, password, or request format",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "429", 
            description = "Too many requests - rate limit exceeded",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "500",
            description = "Internal server error",
            content = @Content(mediaType = "application/json")
        )
    })
    @PostMapping("/reset/{token}")
    public ResponseEntity<Map<String, String>> completePasswordReset(
            @Parameter(description = "Password reset token", required = true)
            @PathVariable String token,
            @Parameter(description = "New password and confirmation", required = true)
            @Valid @RequestBody PasswordResetCompleteRequest request,
            @Parameter(hidden = true) HttpServletRequest httpRequest) {


        if (token == null || token.trim().isEmpty() || 
            token.length() > 255 || !token.matches("^[a-zA-Z0-9\\-_]+$")) {
            return ResponseEntity.status(400)
                    .body(Map.of("error", "Invalid token format."));
        }

        // Validate password confirmation
        if (!request.isPasswordConfirmed()) {
            return ResponseEntity.status(400)
                    .body(Map.of("error", "Password confirmation does not match."));
        }

        // Additional rate limiting for reset completion
        String clientIp = getClientIp(httpRequest);

        String RATE_LIMIT_KEY_HEADER = "password_reset_complete:";

        String rateLimitKey = RATE_LIMIT_KEY_HEADER + clientIp;

        if (rateLimiter.isEnabled() && !rateLimiter.allowRequest(rateLimitKey)) {
            log.warn("Rate limit exceeded for password reset completion from IP: {}", clientIp);
            
            return ResponseEntity.status(429)
                    .body(Map.of("error", "Too many requests. Please try again later."));
        }

        try {
            passwordResetService.completePasswordReset(token, request.getPassword());

            log.info("Password reset completed successfully");


            return ResponseEntity.ok(Map.of(
                    "message", "Password has been reset successfully."
            ));

        } catch (SecurityException e) {
            log.warn("Security error during password reset: {}", e.getMessage());
            return ResponseEntity.status(400)
                    .body(Map.of("error", "Invalid or expired token."));

        } catch (IllegalArgumentException e) {
            log.warn("Validation error during password reset: {}", e.getMessage());
            return ResponseEntity.status(400)
                    .body(Map.of("error", e.getMessage()));

        } catch (Exception e) {
            log.error("Unexpected error during password reset", e);
            return ResponseEntity.status(500)
                    .body(Map.of("error", "An error occurred while resetting password."));
        }
    }

    /**
     * Validate a password reset token (optional endpoint for UI validation).
     */
    @Operation(
        summary = "Validate password reset token",
        description = "Check if a password reset token is valid and not expired"
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200", 
            description = "Token validation result",
            content = @Content(mediaType = "application/json")
        )
    })
    @GetMapping("/reset/{token}/validate")
    public ResponseEntity<Map<String, Object>> validateToken(
        @Parameter(description = "Password reset token to validate", required = true)
        @PathVariable String token) {
        // Basic token format validation
        if (token == null || token.trim().isEmpty() || 
            token.length() > 255 || !token.matches("^[a-zA-Z0-9\\-_]+$")) {
            return ResponseEntity.ok(Map.of(
                    "valid", false,
                    "message", "Token is invalid or expired."
            ));
        }

        try {
            boolean isValid = passwordResetService.validatePasswordResetToken(token);

            return ResponseEntity.ok(Map.of(
                    "valid", true,
                    "message", "Token is valid."
            ));

        } catch (SecurityException e) {
            return ResponseEntity.ok(Map.of(
                    "valid", false,
                    "message", "Token is invalid or expired."
            ));
        }
    }

    /**
     * Extract client IP from request headers, considering proxy headers.
     * Validates and sanitizes IP addresses to prevent header injection.
     */
    private String getClientIp(HttpServletRequest request) {
        // Check X-Forwarded-For header (most common proxy header)
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            String firstIp = xForwardedFor.split(",")[0].trim();
            if (isValidIpAddress(firstIp)) {
                return firstIp;
            }
        }

        // Check X-Real-IP header (nginx proxy)
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty() && isValidIpAddress(xRealIp)) {
            return xRealIp;
        }

        // Fallback to remote address
        return request.getRemoteAddr();
    }

    /**
     * Validates if a string is a valid IP address (IPv4 or IPv6).
     */
    private boolean isValidIpAddress(String ip) {
        if (ip == null || ip.isEmpty() || ip.length() > 45) { // Max IPv6 length is 45
            return false;
        }
        
        // Basic validation for IPv4 and IPv6 patterns
        return ip.matches("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$") || // IPv4
               ip.matches("^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$") || // IPv6 full
               ip.matches("^::1$") || // IPv6 loopback
               ip.matches("^([0-9a-fA-F]{1,4}:)*::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$"); // IPv6 compressed
    }
}
