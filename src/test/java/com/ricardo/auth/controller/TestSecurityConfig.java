package com.ricardo.auth.controller;

import static org.mockito.Mockito.mock;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.User;

/**
 * Test security configuration that allows all requests without authentication.
 * This is used for testing controllers in isolation.
 */
@TestConfiguration
@EnableWebSecurity
public class TestSecurityConfig {

    @Bean
    public SecurityFilterChain testSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .build();
    }

    @Bean
    public PasswordEncoder testPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtService testJwtService() {
        return mock(JwtService.class);
    }

    @Bean
    @Primary
    @SuppressWarnings("unchecked")
    public UserService<User, Long> testUserService() {
        return mock(UserService.class);
    }

    @Bean
    @Primary
    public UserController testUserController() {
        return new UserController(testUserService(), testPasswordEncoder());
    }
}
