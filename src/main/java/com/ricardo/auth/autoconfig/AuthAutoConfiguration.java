package com.ricardo.auth.autoconfig;

import com.ricardo.auth.blocklist.InMemoryTokenBlocklist;
import com.ricardo.auth.blocklist.RedisTokenBlockList;
import com.ricardo.auth.controller.AuthController;
import com.ricardo.auth.controller.UserController;
import com.ricardo.auth.core.*;
import com.ricardo.auth.domain.user.User;
import com.ricardo.auth.ratelimiter.InMemoryRateLimiter;
import com.ricardo.auth.ratelimiter.RedisRateLimiter;
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
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
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

    // ========== COMMON SERVICES ==========

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

        return new RefreshTokenServiceImpl<>(refreshTokenRepository, userService, authProperties);
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
     * @param jwtService     the jwt service
     * @param tokenBlocklist the token blocklist
     * @return the jwt auth filter
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtAuthFilter jwtAuthFilter(JwtService jwtService, TokenBlocklist tokenBlocklist) {
        return new JwtAuthFilter(jwtService, tokenBlocklist);
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

    /**
     * Auth controller auth controller.
     *
     * @param jwtService          the jwt service
     * @param authManager         the auth manager
     * @param refreshTokenService the refresh token service
     * @param authProperties      the auth properties
     * @param tokenBlocklist      the token blocklist
     * @return the auth controller
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "ricardo.auth.controllers", name = "auth.enabled", havingValue = "true", matchIfMissing = true)
    public AuthController authController(
            JwtService jwtService,
            AuthenticationManager authManager,
            RefreshTokenService<User, Long> refreshTokenService,
            AuthProperties authProperties,
            TokenBlocklist tokenBlocklist) {
        return new AuthController(jwtService, authManager, refreshTokenService, authProperties, tokenBlocklist);
    }

    // ========== CONTROLLERS ==========

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

    /**
     * Redis connection factory redis connection factory.
     *
     * @param properties the properties
     * @return the redis connection factory
     */
    @Bean
    public RedisConnectionFactory redisConnectionFactory(AuthProperties properties) {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(
                properties.getRedis().getHost(),
                properties.getRedis().getPort()
        );
        config.setPassword(properties.getRedis().getPassword());
        config.setDatabase(properties.getRedis().getDatabase());

        return new LettuceConnectionFactory(config);
    }

    /**
     * PostgreSQL Refresh Token Repository Configuration (EXPLICIT ONLY)
     */
    @Configuration
    @ConditionalOnProperty(prefix = "ricardo.auth.refresh-tokens.repository", name = "type", havingValue = "POSTGRESQL")
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

    /**
     * The type Memory rate limiter config.
     */
    @Configuration
    @ConditionalOnProperty(prefix = "ricardo.auth.rate-limiter", name = "type", havingValue = "memory")
    static class MemoryRateLimiterConfig {
        /**
         * Memory rate limiter rate limiter.
         *
         * @param authProperties the auth properties
         * @return the rate limiter
         */
        @Bean
        @ConditionalOnMissingBean
        public RateLimiter memoryRateLimiter(AuthProperties authProperties) {
            return new InMemoryRateLimiter(authProperties);
        }

    }

    /**
     * The type Redis rate limiter config.
     */
    @Configuration
    @ConditionalOnClass(name = "org.springframework.data.redis.core.RedisTemplate")
    @ConditionalOnProperty(prefix = "ricardo.auth.rate-limiter", name = "type", havingValue = "redis")
    static class RedisRateLimiterConfig {
        /**
         * Redis rate limiter rate limiter.
         *
         * @param redisTemplate  the redis template
         * @param authProperties the auth properties
         * @return the rate limiter
         */
        @Bean
        @ConditionalOnMissingBean
        public RateLimiter redisRateLimiter(
                RedisTemplate<String, String> redisTemplate,
                AuthProperties authProperties
        ) {
            return new RedisRateLimiter(redisTemplate, authProperties);
        }
    }

    /**
     * The type Redis blocklist config.
     */
    @Configuration
    @ConditionalOnClass(name = "org.springframework.data.redis.core.RedisTemplate")
    @ConditionalOnProperty(prefix = "ricardo.auth.token-blocklist", name = "type", havingValue = "redis")
    static class RedisBlocklistConfig {
        /**
         * Redis token blocklist token blocklist.
         *
         * @param redisTemplate  the redis template
         * @param authProperties the auth properties
         * @return the token blocklist
         */
        @Bean
        @ConditionalOnMissingBean
        public TokenBlocklist redisTokenBlocklist(
                RedisTemplate<String, String> redisTemplate,
                AuthProperties authProperties
        ) {
            return new RedisTokenBlockList(redisTemplate, authProperties.getJwt().getAccessTokenExpiration());
        }
    }

    /**
     * The type Memory blocklist config.
     */
    @Configuration
    @ConditionalOnMissingBean(TokenBlocklist.class)
    static class MemoryBlocklistConfig {
        /**
         * In memory token blocklist token blocklist.
         *
         * @param authProperties the auth properties
         * @return the token blocklist
         */
        @Bean
        public TokenBlocklist inMemoryTokenBlocklist(AuthProperties authProperties) {
            return new InMemoryTokenBlocklist(authProperties);
        }
    }
}