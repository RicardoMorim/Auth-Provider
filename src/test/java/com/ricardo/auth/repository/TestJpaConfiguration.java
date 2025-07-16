package com.ricardo.auth.repository;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.service.PasswordPolicy;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * The type Test jpa configuration.
 */
@TestConfiguration
public class TestJpaConfiguration {

    /**
     * Password encoder password encoder.
     *
     * @return the password encoder
     */
    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Password policy service password policy service.
     *
     * @return the password policy service
     */
    @Bean
    public PasswordPolicyService passwordPolicyService() {
        return new PasswordPolicy(createTestAuthProperties());
    }

    private AuthProperties createTestAuthProperties() {
        AuthProperties properties = new AuthProperties();
        properties.getPasswordPolicy().setMinLength(10);
        properties.getPasswordPolicy().setMaxLength(60);
        properties.getPasswordPolicy().setRequireUppercase(true);
        properties.getPasswordPolicy().setRequireLowercase(true);
        properties.getPasswordPolicy().setRequireDigits(true);
        properties.getPasswordPolicy().setRequireSpecialChars(false);
        return properties;
    }
}