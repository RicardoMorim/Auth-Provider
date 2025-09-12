package com.ricardo.auth.security;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.config.SecurityConfig;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.TokenBlocklist;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * The type Jwt auth filter.
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);
    private static final String ACCESS_TOKEN_COOKIE_NAME = "access_token";
    private static final String UNAUTHORIZED_MESSAGE = "Your Jwt Token is invalid or expired. Please log in again or use your refresh token to get a new access token.";

    private final JwtService jwtService;
    private final TokenBlocklist tokenBlocklist;
    private final AuthProperties authProperties;

    /**
     * Instantiates a new Jwt auth filter.
     *
     * @param jwtService     the jwt service
     * @param tokenBlocklist the token blocklist
     * @param authProperties the auth properties for cookie validation
     */
    public JwtAuthFilter(JwtService jwtService, TokenBlocklist tokenBlocklist, AuthProperties authProperties) {
        this.jwtService = jwtService;
        this.tokenBlocklist = tokenBlocklist;
        this.authProperties = authProperties;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // Skip authentication for public endpoints
        if (SecurityConfig.isPublicEndpoint(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = extractTokenFromCookie(request);
        if (token == null) {
            sendUnauthorizedError(response, "No valid access token found");
            return;
        }

        // Validate cookie security configuration
        if (!validateCookieSecurity(request)) {
            logger.warn("Access token cookie security validation failed for request: {}", request.getRequestURI());
            sendUnauthorizedError(response, "Invalid cookie security configuration");
            return;
        }

        // Validate basic token format
        if (!isValidTokenFormat(token)) {
            sendUnauthorizedError(response, "Invalid token format");
            return;
        }

        // Check if token is blacklisted
        if (tokenBlocklist.isRevoked(token)) {
            logger.debug("Blocked revoked token for request: {}", request.getRequestURI());
            sendUnauthorizedError(response, "Token no longer valid");
            return;
        }

        // Validate and process JWT
        String subject;
        List<String> roles;

        try {
            if (!jwtService.isTokenValid(token)) {
                logger.debug("Invalid JWT token for request: {}", request.getRequestURI());
                sendUnauthorizedError(response, "Invalid authentication");
                return;
            }

            subject = jwtService.extractSubject(token);
            roles = jwtService.extractRoles(token);

        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            logger.debug("Expired JWT token for request: {}", request.getRequestURI());
            sendUnauthorizedError(response, "Authentication expired");
            return;
        } catch (io.jsonwebtoken.security.SignatureException e) {
            logger.warn("JWT signature validation failed for request: {}", request.getRequestURI());
            sendUnauthorizedError(response, "Invalid authentication");
            return;
        } catch (io.jsonwebtoken.MalformedJwtException e) {
            logger.debug("Malformed JWT token for request: {}", request.getRequestURI());
            sendUnauthorizedError(response, "Invalid authentication");
            return;
        } catch (Exception e) {
            logger.error("Unexpected error during JWT validation for request: {}", request.getRequestURI(), e);
            sendUnauthorizedError(response, "Authentication error");
            return;
        }

        // Validate extracted data
        if (subject == null || subject.trim().isEmpty()) {
            logger.debug("JWT token missing subject for request: {}", request.getRequestURI());
            sendUnauthorizedError(response, "Invalid authentication");
            return;
        }

        if (roles == null) {
            logger.debug("JWT token missing roles for request: {}", request.getRequestURI());
            sendUnauthorizedError(response, "Invalid authentication");
            return;
        }

        // Set authentication if not already set
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            setAuthentication(request, subject, roles);
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extract JWT token from HTTP-only cookie
     */
    private String extractTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (ACCESS_TOKEN_COOKIE_NAME.equals(cookie.getName())) {
                String token = cookie.getValue();
                return token;
            }
        }
        return null;
    }

    /**
     * Validate that the access token cookie was set with proper security flags
     * Note: This is a best-effort validation as some cookie attributes may not be
     * accessible from the server side after the cookie is set by the browser
     */
    private boolean validateCookieSecurity(HttpServletRequest request) {
        // Get expected cookie configuration
        AuthProperties.Cookies.AccessCookie cookieConfig = authProperties.getCookies().getAccess();

        // Basic validation - check if we're on HTTPS when secure=true is required
        if (cookieConfig.isSecure() && !request.isSecure()) {
            // If secure=true is configured but we're not on HTTPS, this is suspicious
            // Exception: might be behind a reverse proxy, so we can check headers
            String forwardedProto = request.getHeader("X-Forwarded-Proto");
            String forwardedScheme = request.getHeader("X-Forwarded-Scheme");

            boolean isSecureConnection = "https".equalsIgnoreCase(forwardedProto) ||
                    "https".equalsIgnoreCase(forwardedScheme);

            if (!isSecureConnection) {
                logger.warn("Secure cookie expected but connection is not HTTPS. Request: {}", request.getRequestURI());
                return false;
            }
        }

        // Validate path if configured
        String expectedPath = cookieConfig.getPath();
        if (expectedPath != null && !"/".equals(expectedPath)) {
            String requestPath = request.getRequestURI();
            if (!requestPath.startsWith(expectedPath)) {
                logger.warn("Cookie path mismatch. Expected: {}, Request path: {}", expectedPath, sanitizeForLog(requestPath));
                // This might be too strict, so we'll log but not fail
                // return false;
            }
        }

        // Note: HttpOnly and SameSite attributes cannot be validated server-side
        // as they are not sent back by the browser. These should be validated
        // when setting the cookie.

        return true;
    }

    /**
     * Validate basic JWT token format (xxx.yyy.zzz)
     */
    private boolean isValidTokenFormat(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }

        // Basic JWT format validation
        String[] parts = token.split("\\.");
        return parts.length == 3 &&
                !parts[0].isEmpty() &&
                !parts[1].isEmpty() &&
                !parts[2].isEmpty();
    }

    /**
     * Set Spring Security authentication context
     */
    private void setAuthentication(HttpServletRequest request, String subject, List<String> roles) {
        List<SimpleGrantedAuthority> authorities = roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                subject,
                null,
                authorities
        );

        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);

        logger.debug("Authentication set for user: {} with roles: {}", subject, roles);
    }

    /**
     * Send consistent unauthorized error response
     */
    private void sendUnauthorizedError(HttpServletResponse response, String logMessage) throws IOException {
        logger.debug("Authentication failed: {}", logMessage);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, UNAUTHORIZED_MESSAGE);
    }
    /**
     * Sanitize a string for log output by removing CR and LF characters to prevent log injection.
     */
    private String sanitizeForLog(String input) {
        if (input == null) {
            return null;
        }
        // Remove CR and LF characters
        return input.replace("\n", "").replace("\r", "");
    }
}