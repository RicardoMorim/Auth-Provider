package com.ricardo.auth.service;

import org.hibernate.cfg.Environment;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class JwtServiceImplTest {

    @InjectMocks
    private JwtServiceImpl jwtService;

    @BeforeEach
    void setUp() {
        // Use a secret key that is long enough for the HS256 algorithm
        String secret = Environment.getProperties().getProperty("jwt.secret");
        ReflectionTestUtils.setField(jwtService, "secret", secret);
        ReflectionTestUtils.setField(jwtService, "expiration", 3600000L); // 1 hour
        jwtService.init(); // Manually call PostConstruct method
    }

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