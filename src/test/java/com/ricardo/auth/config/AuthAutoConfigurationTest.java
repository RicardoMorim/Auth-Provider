package com.ricardo.auth.config;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.core.RefreshTokenService;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.user.AppRole;
import com.ricardo.auth.domain.user.User;
import com.ricardo.auth.repository.refreshToken.RefreshTokenRepository;
import com.ricardo.auth.repository.user.DefaultUserJpaRepository;
import com.ricardo.auth.security.JwtAuthFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for AuthAutoConfiguration to ensure proper bean creation and conditional configuration.
 */
@SpringBootTest
@ActiveProfiles("test")
class AuthAutoConfigurationTest {

    @Autowired
    private ApplicationContext applicationContext;

    /**
     * Should auto configure all required beans.
     */
    @Test
    void shouldAutoConfigureAllRequiredBeans() {
        // Core services
        assertThat(applicationContext.getBean(JwtService.class)).isNotNull();
        assertThat(applicationContext.getBean(PasswordPolicyService.class)).isNotNull();
        assertThat(applicationContext.getBean(JwtAuthFilter.class)).isNotNull();
        assertThat(applicationContext.getBean(UserService.class)).isNotNull();
        assertThat(applicationContext.getBean(RefreshTokenService.class)).isNotNull();
        assertThat(applicationContext.getBean(RefreshTokenRepository.class)).isNotNull();
        assertThat(applicationContext.getBean(DefaultUserJpaRepository.class)).isNotNull();

        // Security beans - Use correct bean names
        assertThat(applicationContext.containsBean("authenticationManager")).isTrue();
        assertThat(applicationContext.containsBean("filterChain")).isTrue(); // ✅ Changed from securityFilterChain
        assertThat(applicationContext.containsBean("passwordEncoder")).isTrue();
        assertThat(applicationContext.containsBean("userDetailsService")).isTrue();

        // Controllers
        assertThat(applicationContext.containsBean("authController")).isTrue();
        assertThat(applicationContext.containsBean("userController")).isTrue();
    }

    /**
     * Should load auth properties.
     */
    @Test
    void shouldLoadAuthProperties() {
        AuthProperties properties = applicationContext.getBean(AuthProperties.class);
        assertThat(properties).isNotNull();
        assertThat(properties.getJwt().getSecret()).isEqualTo("dGVzdC1zZWNyZXQtZm9yLWp3dC10b2tlbnMtaW4tdGVzdHMtb25seQ==");
        assertThat(properties.getJwt().getAccessTokenExpiration()).isEqualTo(900000);
    }

    /**
     * Should handle generic user service.
     */
    @Test
    void shouldHandleGenericUserService() {
        UserService<User, AppRole, UUID> userService = applicationContext.getBean(UserService.class);
        assertThat(userService).isNotNull();
    }

    /**
     * Should create complete security setup.
     */
    @Test
    void shouldCreateCompleteSecuritySetup() {
        // Verify complete security setup
        assertThat(applicationContext.containsBean("filterChain")).isTrue(); // ✅ Changed from securityFilterChain
        assertThat(applicationContext.containsBean("authenticationManager")).isTrue();
        assertThat(applicationContext.containsBean("passwordEncoder")).isTrue();
        assertThat(applicationContext.containsBean("userDetailsService")).isTrue();

        // Verify JWT components
        assertThat(applicationContext.getBean(JwtService.class)).isNotNull();
        assertThat(applicationContext.getBean(JwtAuthFilter.class)).isNotNull();

        // Verify controllers work with security
        assertThat(applicationContext.containsBean("authController")).isTrue();
        assertThat(applicationContext.containsBean("userController")).isTrue();
    }

    /**
     * Should configure repositories.
     */
    @Test
    void shouldConfigureRepositories() {
        // Verify repositories are configured
        assertThat(applicationContext.getBean(DefaultUserJpaRepository.class)).isNotNull();
        assertThat(applicationContext.getBean(RefreshTokenRepository.class)).isNotNull();
    }

    /**
     * Should configure all services.
     */
    @Test
    void shouldConfigureAllServices() {
        // Verify all services are configured
        assertThat(applicationContext.getBean(JwtService.class)).isNotNull();
        assertThat(applicationContext.getBean(UserService.class)).isNotNull();
        assertThat(applicationContext.getBean(RefreshTokenService.class)).isNotNull();
        assertThat(applicationContext.getBean(PasswordPolicyService.class)).isNotNull();
    }

    /**
     * Should configure security components.
     */
    @Test
    void shouldConfigureSecurityComponents() {
        // Verify security components
        assertThat(applicationContext.getBean(JwtAuthFilter.class)).isNotNull();
        assertThat(applicationContext.containsBean("userDetailsService")).isTrue();
        assertThat(applicationContext.containsBean("authenticationManager")).isTrue();
    }

    /**
     * Should configure controllers.
     */
    @Test
    void shouldConfigureControllers() {
        // Verify controllers are configured
        assertThat(applicationContext.containsBean("authController")).isTrue();
        assertThat(applicationContext.containsBean("userController")).isTrue();
    }

    /**
     * Should verify bean types.
     */
    @Test
    void shouldVerifyBeanTypes() {
        // Verify specific bean types
        assertThat(applicationContext.getBean(JwtService.class)).isInstanceOf(JwtService.class);
        assertThat(applicationContext.getBean(UserService.class)).isInstanceOf(UserService.class);
        assertThat(applicationContext.getBean(RefreshTokenService.class)).isInstanceOf(RefreshTokenService.class);
        assertThat(applicationContext.getBean(PasswordPolicyService.class)).isInstanceOf(PasswordPolicyService.class);
    }

    /**
     * Should verify auto configuration properties.
     */
    @Test
    void shouldVerifyAutoConfigurationProperties() {
        // Verify auto-configuration properties are loaded
        AuthProperties properties = applicationContext.getBean(AuthProperties.class);
        assertThat(properties.getJwt().getSecret()).isNotBlank();
        assertThat(properties.getJwt().getAccessTokenExpiration()).isGreaterThan(0);
        assertThat(properties.getJwt().getRefreshTokenExpiration()).isGreaterThan(0);
    }

    /**
     * Should verify refresh token configuration.
     */
    @Test
    void shouldVerifyRefreshTokenConfiguration() {
        // Verify refresh token configuration
        assertThat(applicationContext.getBean(RefreshTokenService.class)).isNotNull();
        assertThat(applicationContext.getBean(RefreshTokenRepository.class)).isNotNull();

        AuthProperties properties = applicationContext.getBean(AuthProperties.class);
        assertThat(properties.getRefreshTokens().isEnabled()).isTrue();
        assertThat(properties.getRefreshTokens().getMaxTokensPerUser()).isEqualTo(5);
    }
}