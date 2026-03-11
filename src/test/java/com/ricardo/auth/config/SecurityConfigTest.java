package com.ricardo.auth.config;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.security.JwtAuthFilter;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SecurityConfigTest {

    private SecurityConfig securityConfig;
    private AuthProperties authProperties;

    @BeforeEach
    void setUp() {
        authProperties = new AuthProperties();
        JwtAuthFilter jwtAuthFilter = mock(JwtAuthFilter.class);
        securityConfig = new SecurityConfig(jwtAuthFilter, authProperties);
    }

    @Test
    void isPublicEndpoint_WithKnownPublicEndpoint_ShouldReturnTrue() {
        assertThat(SecurityConfig.isPublicEndpoint("/api/auth/login")).isTrue();
        assertThat(SecurityConfig.isPublicEndpoint("/api/auth/reset/my-token/validate")).isTrue();
    }

    @Test
    void isPublicEndpoint_WithNonPublicEndpoint_ShouldReturnFalse() {
        assertThat(SecurityConfig.isPublicEndpoint("/api/users/123")).isFalse();
    }

    @Test
    void isPublicEndpoint_WithNullPath_ShouldReturnFalse() {
        assertThat(SecurityConfig.isPublicEndpoint(null)).isFalse();
    }

    @Test
    void corsConfigurationSource_ShouldReflectConfiguredValues() {
        authProperties.getCors().setAllowedOrigins(List.of("https://app.example.com"));
        authProperties.getCors().setAllowedMethods(List.of("GET", "POST"));
        authProperties.getCors().setAllowedHeaders(List.of("Content-Type", "X-XSRF-TOKEN"));
        authProperties.getCors().setAllowCredentials(true);
        authProperties.getCors().setMaxAge(1800L);

        CorsConfigurationSource source = securityConfig.corsConfigurationSource();
        CorsConfiguration configuration = source.getCorsConfiguration(new MockHttpServletRequest("GET", "/api/auth/me"));

        assertThat(configuration).isNotNull();
        assertThat(configuration.getAllowedOriginPatterns()).containsExactly("https://app.example.com");
        assertThat(configuration.getAllowedMethods()).containsExactly("GET", "POST");
        assertThat(configuration.getAllowedHeaders()).containsExactly("Content-Type", "X-XSRF-TOKEN");
        assertThat(configuration.getAllowCredentials()).isTrue();
        assertThat(configuration.getMaxAge()).isEqualTo(1800L);
    }

    @Test
    void passwordEncoder_ShouldUseConfiguredStrength() {
        authProperties.getPasswordPolicy().setBcryptStrength(12);

        BCryptPasswordEncoder encoder = (BCryptPasswordEncoder) securityConfig.passwordEncoder();
        String hash = encoder.encode("StrongPass123!");

        assertThat(hash).contains("$12$");
        assertThat(encoder.matches("StrongPass123!", hash)).isTrue();
    }

    @Test
    void authenticationEntryPoint_ShouldReturnUnauthorizedJson() throws ServletException, IOException {
        AuthenticationEntryPoint entryPoint = securityConfig.authenticationEntryPoint();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/protected");
        MockHttpServletResponse response = new MockHttpServletResponse();

        entryPoint.commence(request, response, new BadCredentialsException("Invalid credentials"));

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).isEqualTo("application/json");
        assertThat(response.getContentAsString()).isEqualTo("{\"message\":\"Unauthorized\"}");
    }
}
