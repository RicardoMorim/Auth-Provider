package com.ricardo.auth.config;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.IpResolver;
import com.ricardo.auth.core.RateLimiter;
import com.ricardo.auth.ratelimiter.RateLimiterFilter;
import com.ricardo.auth.security.JwtAuthFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
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
            "/api/auth/.well-known/jwks.json"
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
            "/api/auth/.well-known/jwks.json"
    };

    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    @Autowired
    private JwtAuthFilter jwtAuthFilter;
    @Autowired
    private AuthProperties authProperties;

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

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
    @ConditionalOnMissingBean(PasswordEncoder.class)
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(authProperties.getPasswordPolicy().getBcryptStrength());
    }

    /**
     * Authentication manager authentication manager.
     *
     * @param config the config
     * @return the authentication manager
     * @throws Exception the exception
     */
    @Bean
    @ConditionalOnMissingBean(AuthenticationManager.class)
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Custom authentication entry point that returns 401 without leaking internal details.
     *
     * @return the authentication entry point
     */
    @Bean
    @ConditionalOnMissingBean(AuthenticationEntryPoint.class)
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, authException) -> {
            logger.debug("Authentication failed: {}", authException.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"message\":\"Unauthorized\"}");
        };
    }

    /**
     * CORS configuration source for cross-origin requests.
     * Automatically configured to work with cookie authentication.
     *
     * @return the cors configuration source
     */
    @Bean
    @ConditionalOnMissingBean(CorsConfigurationSource.class)
    public CorsConfigurationSource corsConfigurationSource() {
        AuthProperties.Cors corsConfig = authProperties.getCors();
        CorsConfiguration configuration = new CorsConfiguration();

        List<String> origins = corsConfig.getAllowedOrigins();
        if (origins == null || origins.isEmpty()) {
            logger.warn("No CORS allowed origins configured (ricardo.auth.cors.allowed-origins). " +
                    "Cross-origin requests will be rejected. Configure specific origins for your frontend.");
        } else if (origins.contains("*")) {
            logger.warn("CORS is configured with wildcard '*' origin. " +
                    "This is insecure for cookie-based authentication. " +
                    "Configure specific origins via ricardo.auth.cors.allowed-origins");
        }

        configuration.setAllowedOriginPatterns(origins);
        configuration.setAllowedMethods(corsConfig.getAllowedMethods());
        configuration.setAllowedHeaders(corsConfig.getAllowedHeaders());
        configuration.setAllowCredentials(corsConfig.isAllowCredentials());
        configuration.setMaxAge(corsConfig.getMaxAge());

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
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain filterChain(HttpSecurity http, @Qualifier("generalRateLimiter") RateLimiter rateLimiter, IpResolver ipResolver) throws Exception {
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
                .addFilterBefore(new RateLimiterFilter(rateLimiter, ipResolver), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

}