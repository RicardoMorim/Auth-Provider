package com.ricardo.auth.service;

import com.ricardo.auth.core.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests for JwtService.
 */
@SpringBootTest
@ActiveProfiles("test")
class JwtServiceIntegrationTest {

    @Autowired
    private JwtService jwtService;

    @Test
    void generateToken_shouldCreateValidToken() {
        // Arrange
        String subject = "test@example.com";
        List<SimpleGrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));

        // Act
        String token = jwtService.generateToken(subject, authorities);

        // Assert
        assertThat(token).isNotNull();
        assertThat(jwtService.extractSubject(token)).isEqualTo(subject);
        assertThat(jwtService.extractRoles(token)).contains("ROLE_USER");
    }

    @Test
    void isTokenValid_shouldReturnTrue_forValidToken() {
        // Arrange
        String token = jwtService.generateToken("test@user.com", Collections.emptyList());

        // Act & Assert
        assertTrue(jwtService.isTokenValid(token));
    }

    @Test
    void isTokenValid_shouldReturnFalse_forInvalidToken() {
        // Act & Assert
        assertFalse(jwtService.isTokenValid("invalid.token.string"));
    }
}