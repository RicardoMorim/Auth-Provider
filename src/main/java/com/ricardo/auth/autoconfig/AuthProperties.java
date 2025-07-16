package com.ricardo.auth.autoconfig;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for Ricardo Auth Starter.
 * This class enables IDE auto-completion on the application.properties file and allows users to configure some
 * settings without needing to write code.
 * Also enables users to create their own custom configuration class that extends this one, allowing them to
 * override the default values.
 */
@ConfigurationProperties(prefix = "ricardo.auth")
public class AuthProperties {

    /**
     * Whether auth is enabled
     */
    private boolean enabled = true;

    /**
     * JWT configuration
     */
    private Jwt jwt = new Jwt();

    /**
     * Controller configuration
     */
    private Controllers controllers = new Controllers();

    /**
     * Password policy configuration
     */
    private PasswordPolicy passwordPolicy = new PasswordPolicy();

    /**
     * Refresh token configuration
     */
    private RefreshTokens refreshTokens = new RefreshTokens();

    /**
     * The type Refresh tokens.
     */
    @Getter
    @Setter
    public static class RefreshTokens {
        private boolean enabled = true;
        private int maxTokensPerUser = 5;
        private boolean rotateOnRefresh = true;
        private long cleanupInterval = 3600000L;
        private boolean autoCleanup = true;

        /**
         * Repository configuration specifically for refresh tokens
         */
        private RefreshTokenRepository repository = new RefreshTokenRepository();
    }

    /**
     * The type Refresh token repository.
     */
    @Getter
    @Setter
    public static class RefreshTokenRepository {
        /**
         * Repository type for refresh tokens: jpa, postgresql
         */
        private String type = RefreshTokenRepositoryType.JPA.toString().toLowerCase();

        /**
         * Database-specific settings for refresh tokens
         */
        private Database database = new Database();
    }

    /**
     * The type Database.
     */
    @Getter
    @Setter
    public static class Database {
        private String refreshTokensTable = "refresh_tokens";
        private String schema;
        private String url;
        private String driverClassName;
    }

    /**
     * The enum Refresh token repository type.
     */
    public enum RefreshTokenRepositoryType {
        /**
         * Jpa refresh token repository type.
         */
        JPA ("jpa"),
        /**
         * Postgresql refresh token repository type.
         */
        POSTGRESQL ("postgresql");

        @Getter
        private final String value;

        RefreshTokenRepositoryType(String value) {
            this.value = value;
        }

        @Override
        public final String toString() {
            return value;
        }
    }

    /**
     * The type Jwt.
     */
    @Getter
    @Setter
    public static class Jwt {
        /**
         * JWT secret key (Base64 encoded) - REQUIRED
         */
        private String secret;

        /**
         * JWT access token expiration time in milliseconds (default: 15 minutes)
         */
        private long accessTokenExpiration = 900000L; // 15 minutes

        /**
         * JWT refresh token expiration time in milliseconds (default: 7 days)
         */
        private long refreshTokenExpiration = 604800000L; // 7 days
    }


    /**
     * The type Controllers.
     */
    @Getter
    @Setter
    public static class Controllers {
        private Controller auth = new Controller();
        private Controller user = new Controller();

        /**
         * The type Controller.
         */
        @Getter
        @Setter
        public static class Controller {
            private boolean enabled = true;
        }
    }

    /**
     * Password policy configuration
     */
    @Setter
    @Getter
    public static class PasswordPolicy {
        /**
         * Minimum password length
         */
        private int minLength = 8;

        /**
         * Maximum password length
         */
        private int maxLength = 128;

        /**
         * Require at least one uppercase letter
         */
        private boolean requireUppercase = true;

        /**
         * Require at least one lowercase letter
         */
        private boolean requireLowercase = true;

        /**
         * Require at least one digit
         */
        private boolean requireDigits = true;

        /**
         * Require at least one special character
         */
        private boolean requireSpecialChars = false;

        /**
         * Allowed special characters
         */
        private String allowedSpecialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";

        /**
         * Prevent common passwords (basic check)
         */
        private boolean preventCommonPasswords = true;

        /**
         * Path to file containing common passwords (one per line)
         * Required when preventCommonPasswords is true
         */
        private String commonPasswordsFilePath = "/commonpasswords.txt";
    }

    /**
     * Is enabled boolean.
     *
     * @return the boolean
     */
// Root level getters and setters
    public boolean isEnabled() { return enabled; }

    /**
     * Sets enabled.
     *
     * @param enabled the enabled
     */
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    /**
     * Gets jwt.
     *
     * @return the jwt
     */
    public Jwt getJwt() { return jwt; }

    /**
     * Sets jwt.
     *
     * @param jwt the jwt
     */
    public void setJwt(Jwt jwt) { this.jwt = jwt; }

    /**
     * Gets controllers.
     *
     * @return the controllers
     */
    public Controllers getControllers() { return controllers; }

    /**
     * Sets controllers.
     *
     * @param controllers the controllers
     */
    public void setControllers(Controllers controllers) { this.controllers = controllers; }

    /**
     * Gets password policy.
     *
     * @return the password policy
     */
    public PasswordPolicy getPasswordPolicy() { return passwordPolicy; }

    /**
     * Sets password policy.
     *
     * @param passwordPolicy the password policy
     */
    public void setPasswordPolicy(PasswordPolicy passwordPolicy) { this.passwordPolicy = passwordPolicy; }

    /**
     * Gets refresh tokens.
     *
     * @return the refresh tokens
     */
    public RefreshTokens getRefreshTokens() { return refreshTokens; }

    /**
     * Sets refresh tokens.
     *
     * @param refreshTokens the refresh tokens
     */
    public void setRefreshTokens(RefreshTokens refreshTokens) { this.refreshTokens = refreshTokens; }
}