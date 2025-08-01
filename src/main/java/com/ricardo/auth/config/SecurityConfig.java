package com.ricardo.auth.config;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.RateLimiter;
import com.ricardo.auth.ratelimiter.RateLimiterFilter;
import com.ricardo.auth.security.JwtAuthFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * The type Security config.
 */
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final static String[] PUBLIC_ENDPOINTS = {
            "/api/auth/login",
            "/api/users/create",
            "/api/auth/refresh"
    };
    @Autowired
    private JwtAuthFilter jwtAuthFilter;
    @Autowired
    private AuthProperties authProperties;

    /**
     * Is public endpoint boolean.
     *
     * @param url the url
     * @return the boolean
     */
    public static boolean isPublicEndpoint(String url) {
        for (String endpoint : PUBLIC_ENDPOINTS) {
            if (url.toLowerCase().equals(endpoint)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Password encoder password encoder.
     *
     * @return the password encoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Authentication manager authentication manager.
     *
     * @param config the config
     * @return the authentication manager
     * @throws Exception the exception
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Custom authentication entry point that returns 401 instead of 403.
     *
     * @return the authentication entry point
     */
    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, authException) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"message\":\"Authentication Failed: " + authException.getMessage() + "\"}");
        };
    }

    /**
     * Filter chain security filter chain.
     *
     * @param http        the http
     * @param rateLimiter the rate limiter
     * @return the security filter chain
     * @throws Exception the exception
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    public SecurityFilterChain filterChain(HttpSecurity http, RateLimiter rateLimiter) throws Exception {
        // SECURITY NOTE: CSRF protection disabled for JWT-based stateless API
        // This is safe because:
        // 1. No session cookies (SessionCreationPolicy.STATELESS)
        // 2. JWT tokens require explicit Authorization header
        // 3. Malicious sites cannot access JWT tokens due to browser security
        // 4. No traditional form-based authentication endpoints
        if (authProperties.isRedirectHttps()) {
            http.redirectToHttps(withDefaults());
        }
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                        .anyRequest().authenticated()
                )

                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> ex.authenticationEntryPoint(authenticationEntryPoint()))
                .addFilterBefore(new RateLimiterFilter(rateLimiter), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

}