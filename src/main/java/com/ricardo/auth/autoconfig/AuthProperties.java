package com.ricardo.auth.autoconfig;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for Ricardo Auth Starter
 * This class enables IDE auto-completion on the application.properties file and allows users to configure some settings without needing to write code
 * Also enables users to create their own custom configuration class that extends this one, allowing them to override the default values.
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
     * Refresh token configuration
     */
    @Getter
    @Setter
    public static class RefreshTokens {
        /**
         * Whether refresh tokens are enabled
         */
        private boolean enabled = true;

        /**
         * Storage type for refresh tokens
         */
        private Storage storage = new Storage();

        /**
         * Maximum number of concurrent refresh tokens per user (0 = unlimited)
         */
        private int maxTokensPerUser = 5;

        /**
         * Whether to rotate refresh tokens on each use
         */
        private boolean rotateOnRefresh = true;

        /**
         * Cleanup interval for expired tokens in milliseconds (default: 1 hour)
         */
        private long cleanupInterval = 3600000L;

        /**
         * Storage configuration for refresh tokens
         */
        @Getter
        @Setter
        public static class Storage {
            /**
             * Storage type: jpa, redis, mongodb, memory
             */
            private String type = "jpa";

            /**
             * Redis-specific configuration
             */
            private Redis redis = new Redis();

            /**
             * JPA-specific configuration
             */
            private Jpa jpa = new Jpa();

            /**
             * MongoDB-specific configuration
             */
            private MongoDB mongodb = new MongoDB();

            /**
             * Redis storage configuration
             */
            @Getter
            @Setter
            public static class Redis {
                /**
                 * TTL buffer time in milliseconds (extra time beyond token expiry)
                 */
                private long ttlBuffer = 600000L; // 10 minutes

                /**
                 * Redis key prefix for refresh tokens
                 */
                private String keyPrefix = "refresh_token:";

                /**
                 * Redis key prefix for user token tracking
                 */
                private String userTokensPrefix = "user_tokens:";
            }

            /**
             * JPA storage configuration
             */
            @Getter
            @Setter
            public static class Jpa {
                /**
                 * Table name for refresh tokens
                 */
                private String tableName = "refresh_tokens";

                /**
                 * Enable automatic cleanup of expired tokens
                 */
                private boolean autoCleanup = true;
            }

            /**
             * MongoDB storage configuration
             */
            @Getter
            @Setter
            public static class MongoDB {
                /**
                 * Collection name for refresh tokens
                 */
                private String collectionName = "refresh_tokens";

                /**
                 * Enable TTL index for automatic expiration
                 */
                private boolean enableTtlIndex = true;
            }
        }
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

    // Root level getters and setters
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public Jwt getJwt() { return jwt; }
    public void setJwt(Jwt jwt) { this.jwt = jwt; }

    public Controllers getControllers() { return controllers; }
    public void setControllers(Controllers controllers) { this.controllers = controllers; }

    public PasswordPolicy getPasswordPolicy() { return passwordPolicy; }
    public void setPasswordPolicy(PasswordPolicy passwordPolicy) { this.passwordPolicy = passwordPolicy; }

    public RefreshTokens getRefreshTokens() { return refreshTokens; }
    public void setRefreshTokens(RefreshTokens refreshTokens) { this.refreshTokens = refreshTokens; }
}