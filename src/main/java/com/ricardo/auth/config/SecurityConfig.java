package com.ricardo.auth.config;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.RateLimiter;
import com.ricardo.auth.ratelimiter.RateLimiterFilter;
import com.ricardo.auth.security.JwtAuthFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * The type Security config.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    // Refresh token, login, password reset and user creation are public endpoints
    private final static String[] JWT_PUBLIC_ENDPOINTS = {
            "/api/auth/refresh",
            "/api/auth/login",
            "/api/auth/reset-request",
            "/api/auth/reset/*/validate",
            "/api/auth/reset/**",
            "/api/users/create",
            "/swagger-ui/**",
            "/v3/api-docs/**",
            "/api/csrf-token",
    };

    // Only login and user creation are public for CSRF (Refresh routes need CSRF protection)
    private final static String[] CSRF_PUBLIC_ENDPOINTS = {
            "/api/auth/login",
            "/api/users/create",
            "/api/auth/reset-request",
            "/api/auth/reset/**",
            "/swagger-ui/**",
            "/v3/api-docs/**",
            "/api/csrf-token",
    };

    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

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
        if (url == null) return false;
        String path = url.toLowerCase();
        for (String endpoint : JWT_PUBLIC_ENDPOINTS) {
            if (PATH_MATCHER.match(endpoint.toLowerCase(), path)) {
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
     * CORS configuration source for cross-origin requests.
     * Automatically configured to work with cookie authentication.
     *
     * @return the cors configuration source
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Allow specific origins (configure via application.properties)
        configuration.setAllowedOriginPatterns(List.of("*"));

        // Allow common HTTP methods
        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"
        ));

        // Allow common headers including CSRF token
        configuration.setAllowedHeaders(Arrays.asList(
                "Content-Type", "X-Requested-With", "Authorization",
                "X-XSRF-TOKEN", "Cache-Control", "Accept"
        ));

        // Allow credentials for cookie authentication
        configuration.setAllowCredentials(true);

        // Cache preflight requests for 1 hour
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
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
    public SecurityFilterChain filterChain(HttpSecurity http, @Qualifier("generalRateLimiter") RateLimiter rateLimiter) throws Exception {
        if (authProperties.isRedirectHttps()) {
            http.redirectToHttps(withDefaults());
        }
        return http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .ignoringRequestMatchers(CSRF_PUBLIC_ENDPOINTS)
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(JWT_PUBLIC_ENDPOINTS).permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> ex.authenticationEntryPoint(authenticationEntryPoint()))
                .addFilterBefore(new RateLimiterFilter(rateLimiter), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

}