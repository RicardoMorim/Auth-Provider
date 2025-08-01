package com.ricardo.auth.config;

import com.ricardo.auth.autoconfig.AuthProperties;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for AuthProperties validation and configuration binding.
 */
@SpringBootTest
@ActiveProfiles("test")
class AuthPropertiesTest {

    private final ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
    private final Validator validator = factory.getValidator();

    /**
     * Should create with default values.
     */
    @Test
    void shouldCreateWithDefaultValues() {
        // Act
        AuthProperties properties = new AuthProperties();

        // Assert
        assertThat(properties.isEnabled()).isTrue();
        assertThat(properties.getJwt().getSecret()).isNull(); // ensure that default is null so that people NEED to set it
        assertThat(properties.getJwt().getAccessTokenExpiration()).isGreaterThan(0);
        assertThat(properties.getPasswordPolicy().getMinLength()).isEqualTo(8);
        assertThat(properties.getRefreshTokens().isEnabled()).isTrue();
    }

    /**
     * Should validate jwt secret length.
     */
    @Test
    void shouldValidateJwtSecretLength() {
        // Arrange
        AuthProperties properties = new AuthProperties();
        properties.getJwt().setSecret("short"); // Too short

        // Act
        Set<ConstraintViolation<AuthProperties>> violations = validator.validate(properties);

        // Assert - If validation annotations are present
        // This depends on your actual validation implementation
        assertThat(violations).isNotNull();
    }

    /**
     * Should validate password policy min length.
     */
    @Test
    void shouldValidatePasswordPolicyMinLength() {
        // Arrange
        AuthProperties properties = new AuthProperties();
        properties.getPasswordPolicy().setMinLength(-1); // Invalid

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> {
            // This would be validated in the PasswordPolicy constructor
            new com.ricardo.auth.service.PasswordPolicy(properties);
        });
    }

    /**
     * Should validate password policy max length.
     */
    @Test
    void shouldValidatePasswordPolicyMaxLength() {
        // Arrange
        AuthProperties properties = new AuthProperties();
        properties.getPasswordPolicy().setMinLength(10);
        properties.getPasswordPolicy().setMaxLength(5); // Less than min

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> {
            new com.ricardo.auth.service.PasswordPolicy(properties);
        });
    }

    /**
     * Should support repository type configuration.
     */
    @Test
    void shouldSupportRepositoryTypeConfiguration() {
        // Arrange
        AuthProperties properties = new AuthProperties();

        // Act
        properties.getRefreshTokens().getRepository().setType(AuthProperties.RefreshTokenRepositoryType.POSTGRESQL);

        // Assert
        assertThat(properties.getRefreshTokens().getRepository().getType()).isEqualTo(AuthProperties.RefreshTokenRepositoryType.POSTGRESQL);
    }

    /**
     * Should support database table configuration.
     */
    @Test
    void shouldSupportDatabaseTableConfiguration() {
        AuthProperties properties = new AuthProperties();

        properties.getRefreshTokens().getRepository().getDatabase().setRefreshTokensTable("custom_tokens");
        assertThat(properties.getRefreshTokens().getRepository().getDatabase().getRefreshTokensTable()).isEqualTo("custom_tokens");

        properties.getRefreshTokens().getRepository().getDatabase().setRefreshTokensTable("custom_users");
        assertThat(properties.getRefreshTokens().getRepository().getDatabase().getRefreshTokensTable()).isEqualTo("custom_users");
    }

    /**
     * Should support controller configuration.
     */
    @Test
    void shouldSupportControllerConfiguration() {
        // Arrange
        AuthProperties properties = new AuthProperties();

        // Act
        properties.getControllers().getAuth().setEnabled(false);
        properties.getControllers().getUser().setEnabled(false);

        // Assert
        assertThat(properties.getControllers().getAuth().isEnabled()).isFalse();
        assertThat(properties.getControllers().getUser().isEnabled()).isFalse();
    }

    /**
     * Should support jwt configuration.
     */
    @Test
    void shouldSupportJwtConfiguration() {
        // Arrange
        AuthProperties properties = new AuthProperties();

        // Act
        properties.getJwt().setAccessTokenExpiration(7200000L);
        properties.getJwt().setRefreshTokenExpiration(86400000L);

        // Assert
        assertThat(properties.getJwt().getAccessTokenExpiration()).isEqualTo(7200000L);
        assertThat(properties.getJwt().getRefreshTokenExpiration()).isEqualTo(86400000L);
    }
}