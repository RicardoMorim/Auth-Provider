package com.ricardo.auth.autoconfig;

import com.ricardo.auth.controller.AuthController;
import com.ricardo.auth.controller.UserController;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.User;
import com.ricardo.auth.repository.DefaultUserJpaRepository;
import com.ricardo.auth.security.JwtAuthFilter;
import com.ricardo.auth.service.JwtServiceImpl;
import com.ricardo.auth.service.PasswordPolicy;
import com.ricardo.auth.service.UserDetailsServiceImpl;
import com.ricardo.auth.service.UserServiceImpl;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Auto-configuration for Ricardo Auth Starter.
 * <p>
 * This configuration is automatically activated when the starter is on the classpath
 * and can be disabled by setting ricardo.auth.enabled=false
 */
@AutoConfiguration
@ConditionalOnClass({User.class, JwtService.class})
@ConditionalOnProperty(prefix = "ricardo.auth", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AuthProperties.class)
@ComponentScan(basePackages = "com.ricardo.auth")
@EntityScan(basePackages = "com.ricardo.auth.domain")
@EnableJpaRepositories(basePackages = "com.ricardo.auth.repository")
public class AuthAutoConfiguration {

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
    @ConditionalOnMissingBean(name = "userService")
    public UserService<User, Long> defaultUserService(
            DefaultUserJpaRepository userRepository) {
        return new UserServiceImpl<>(userRepository);
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
     * Auth controller auth controller.
     *
     * @param jwtService  the jwt service
     * @param authManager the auth manager
     * @return the auth controller
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "ricardo.auth.controllers", name = "auth.enabled", havingValue = "true", matchIfMissing = true)
    public AuthController authController(JwtService jwtService, AuthenticationManager authManager) {
        return new AuthController(jwtService, authManager);
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
    public UserController userController(UserService<User, Long> userService, PasswordEncoder passwordEncoder, PasswordPolicyService passwordPolicyService) {
        return new UserController(userService, passwordEncoder, passwordPolicyService);
    }


}