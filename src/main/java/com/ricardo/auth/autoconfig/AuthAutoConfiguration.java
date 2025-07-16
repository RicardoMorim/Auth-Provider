package com.ricardo.auth.autoconfig;

import com.ricardo.auth.controller.AuthController;
import com.ricardo.auth.controller.UserController;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.core.RefreshTokenService;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.user.User;
import com.ricardo.auth.repository.refreshToken.DefaultJpaRefreshTokenRepository;
import com.ricardo.auth.repository.refreshToken.PostgreSQLRefreshTokenRepository;
import com.ricardo.auth.repository.refreshToken.RefreshTokenRepository;
import com.ricardo.auth.repository.user.DefaultUserJpaRepository;
import com.ricardo.auth.repository.user.UserRepository;
import com.ricardo.auth.security.JwtAuthFilter;
import com.ricardo.auth.service.*;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;

/**
 * Auto-configuration for Ricardo Auth Starter.
 * <p>
 * This configuration automatically selects the appropriate database driver and repository implementation
 * based on the configuration properties and available dependencies.
 */
@AutoConfiguration
@ConditionalOnClass({User.class, JwtService.class})
@ConditionalOnProperty(prefix = "ricardo.auth", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AuthProperties.class)
@ComponentScan(basePackages = "com.ricardo.auth")
@EntityScan(basePackages = "com.ricardo.auth.domain")
@EnableJpaRepositories(
        basePackages = "com.ricardo.auth.repository",
        includeFilters = @ComponentScan.Filter(
                type = FilterType.ASSIGNABLE_TYPE,
                classes = {DefaultUserJpaRepository.class, DefaultJpaRefreshTokenRepository.class}
        )
)
public class AuthAutoConfiguration {

    // ========== REFRESH TOKEN REPOSITORY (CONFIGURABLE) ==========


     // JPA Refresh Token Repository Configuration (DEFAULT) (Spring data will automatically bean scan this)


    /**
     * PostgreSQL Refresh Token Repository Configuration (EXPLICIT ONLY)
     */
    @Configuration
    @ConditionalOnProperty(prefix = "ricardo.auth.refresh-tokens.repository", name = "type", havingValue = "postgresql")
    @ConditionalOnMissingBean(RefreshTokenRepository.class)
    static class PostgreSQLRefreshTokenRepositoryConfiguration {
        /**
         * Refresh token repository refresh token repository.
         *
         * @param dataSource     the data source
         * @param authProperties the auth properties
         * @return the refresh token repository
         */
        @Bean
        public RefreshTokenRepository refreshTokenRepository(
                DataSource dataSource,
                AuthProperties authProperties) {
            System.out.println("✅ Creating PostgreSQL RefreshTokenRepository (EXPLICIT)");
            return new PostgreSQLRefreshTokenRepository(dataSource, authProperties);
        }
    }

    // ========== COMMON SERVICES ==========

    /**
     * Jwt service jwt service.
     *
     * @param authProperties the auth properties
     * @return the jwt service
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtService jwtService(AuthProperties authProperties) {
        return new JwtServiceImpl(authProperties);
    }

    /**
     * User service user service.
     *
     * @param userRepository the user repository
     * @return the user service
     */
    @Bean
    @ConditionalOnMissingBean
    public UserService<User, Long> userService(UserRepository<User, Long> userRepository) {
        return new UserServiceImpl<>(userRepository);
    }

    /**
     * Refresh token service refresh token service.
     *
     * @param refreshTokenRepository the refresh token repository
     * @param userService            the user service
     * @param authProperties         the auth properties
     * @return the refresh token service
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "ricardo.auth.refresh-tokens", name = "enabled", havingValue = "true", matchIfMissing = true)
    public RefreshTokenService<User, Long> refreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            UserService<User, Long> userService,
            AuthProperties authProperties) {

        Long expiryDuration = authProperties.getJwt().getRefreshTokenExpiration() / 1000;
        return new RefreshTokenServiceImpl<>(refreshTokenRepository, userService, expiryDuration);
    }

    /**
     * User details service user details service.
     *
     * @param userService the user service
     * @return the user details service
     */
    @Bean
    @ConditionalOnMissingBean
    public UserDetailsServiceImpl userDetailsService(UserService<User, Long> userService) {
        return new UserDetailsServiceImpl(userService);
    }

    /**
     * Jwt auth filter jwt auth filter.
     *
     * @param jwtService the jwt service
     * @return the jwt auth filter
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtAuthFilter jwtAuthFilter(JwtService jwtService) {
        return new JwtAuthFilter(jwtService);
    }

    /**
     * Password policy service password policy service.
     *
     * @param authProperties the auth properties
     * @return the password policy service
     */
    @Bean
    @ConditionalOnMissingBean
    public PasswordPolicyService passwordPolicyService(AuthProperties authProperties) {
        return new PasswordPolicy(authProperties);
    }

    // ========== CONTROLLERS ==========

    /**
     * Auth controller auth controller.
     *
     * @param jwtService          the jwt service
     * @param authManager         the auth manager
     * @param refreshTokenService the refresh token service
     * @param authProperties      the auth properties
     * @return the auth controller
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "ricardo.auth.controllers", name = "auth.enabled", havingValue = "true", matchIfMissing = true)
    public AuthController authController(
            JwtService jwtService,
            AuthenticationManager authManager,
            RefreshTokenService<User, Long> refreshTokenService,
            AuthProperties authProperties) {
        return new AuthController(jwtService, authManager, refreshTokenService, authProperties);
    }

    /**
     * User controller user controller.
     *
     * @param userService           the user service
     * @param passwordEncoder       the password encoder
     * @param passwordPolicyService the password policy service
     * @return the user controller
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "ricardo.auth.controllers", name = "user.enabled", havingValue = "true", matchIfMissing = true)
    public UserController userController(
            UserService<User, Long> userService,
            PasswordEncoder passwordEncoder,
            PasswordPolicyService passwordPolicyService) {
        return new UserController(userService, passwordEncoder, passwordPolicyService);
    }
}