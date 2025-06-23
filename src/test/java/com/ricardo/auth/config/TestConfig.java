package com.ricardo.auth.config;

import com.ricardo.auth.controller.UserController;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.User;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Test configuration to ensure controllers are loaded during testing,
 * regardless of conditional annotations.
 */
@TestConfiguration
public class TestConfig {

    /**
     * Creates a UserController bean for tests, overriding the conditional behavior.
     * This ensures the controller is available during integration tests while
     * maintaining the plug-and-play architecture in production.
     *
     * @param userService     the user service
     * @param passwordEncoder the password encoder
     * @return the user controller
     */
    @Bean
    @Primary
    public UserController testUserController(UserService<User, Long> userService, PasswordEncoder passwordEncoder) {
        return new UserController(userService, passwordEncoder);
    }
}
