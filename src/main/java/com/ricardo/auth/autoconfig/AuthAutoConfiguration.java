package com.ricardo.auth.autoconfig;

import com.ricardo.auth.config.SecurityConfig;
import com.ricardo.auth.controller.AuthController;
import com.ricardo.auth.controller.UserController;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.User;
import com.ricardo.auth.repository.UserJpaRepository;
import com.ricardo.auth.security.JwtAuthFilter;
import com.ricardo.auth.service.JwtServiceImpl;
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
 *
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

    @Bean
    @ConditionalOnMissingBean
    public JwtService jwtService() {
        return new JwtServiceImpl();
    }

    @Bean
    @ConditionalOnMissingBean
    public UserService<User, Long> userService(UserJpaRepository userRepository) {
        return new UserServiceImpl(userRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public UserDetailsServiceImpl userDetailsService(UserService<User, Long> userService) {
        return new UserDetailsServiceImpl(userService);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthFilter jwtAuthFilter(JwtService jwtService) {
        return new JwtAuthFilter(jwtService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "ricardo.auth.controllers", name = "auth.enabled", havingValue = "true", matchIfMissing = true)
    public AuthController authController(JwtService jwtService, AuthenticationManager authManager) {
        return new AuthController(jwtService, authManager);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "ricardo.auth.controllers", name = "user.enabled", havingValue = "true", matchIfMissing = true)
    public UserController userController(UserService<User, Long> userService, PasswordEncoder passwordEncoder) {
        return new UserController(userService, passwordEncoder);
    }
}