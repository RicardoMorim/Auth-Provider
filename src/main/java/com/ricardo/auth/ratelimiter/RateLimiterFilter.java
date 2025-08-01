package com.ricardo.auth.ratelimiter;

import com.ricardo.auth.core.RateLimiter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * The type Rate limiter filter.
 */
@ConditionalOnProperty(prefix = "ricardo.auth.rate-limiter", name = "type", havingValue = "memory")
public class RateLimiterFilter extends OncePerRequestFilter {
    private final RateLimiter rateLimiter;

    /**
     * Instantiates a new Rate limiter filter.
     *
     * @param rateLimiter the rate limiter
     */
    public RateLimiterFilter(RateLimiter rateLimiter) {
        this.rateLimiter = rateLimiter;
    }

    /**
     * Do filter internal.
     *
     * @param request     the request
     * @param response    the response
     * @param filterChain the filter chain
     * @throws ServletException the servlet exception
     * @throws IOException      the io exception
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        if (!rateLimiter.isEnabled()) {
            filterChain.doFilter(request, response);
            return;
        }

        String key = getClientIdentifier(request);

        if (!rateLimiter.allowRequest(key)) {
            response.sendError(HttpStatus.TOO_MANY_REQUESTS.value(), "Rate limit exceeded");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private String getClientIdentifier(HttpServletRequest request) {
        return Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
                .map(Authentication::getName)
                .orElseGet(request::getRemoteAddr);
    }
}