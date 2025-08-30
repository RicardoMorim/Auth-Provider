package com.ricardo.auth.autoconfig;

import jakarta.validation.constraints.Min;
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
@Getter
@Setter
@ConfigurationProperties(prefix = "ricardo.auth")
public class AuthProperties {

    /**
     * Whether auth is enabled
     */
    private boolean enabled = true;

    /**
     * Whether to redirect HTTP to HTTPS
     */
    private boolean redirectHttps = true;

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
     * Rate limiter configuration
     */
    private RateLimiter rateLimiter = new RateLimiter();

    /**
     * Token blocklist configuration
     */
    private TokenBlocklist tokenBlocklist = new TokenBlocklist();

    /**
     * Redis configuration
     */
    private Redis redis = new Redis();

    /**
     * Cookie configuration
     */
    private Cookies cookies = new Cookies();

    private Repositories repository = new Repositories();

    /**
     * Repository types for refresh tokens
     */
    public enum RepositoryType {
        JPA("jpa"),
        POSTGRESQL("postgresql");

        @Getter
        private final String value;

        RepositoryType(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    /**
     * Storage types for rate limiter and token blocklist
     */
    public enum StorageType {
        MEMORY("memory"),
        REDIS("redis");

        @Getter
        private final String value;

        StorageType(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    /**
     * Cookie SameSite attribute values
     */
    public enum SameSitePolicy {
        STRICT("Strict"),
        LAX("Lax"),
        NONE("None");

        @Getter
        private final String value;

        SameSitePolicy(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    /**
     * JWT configuration properties
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
        private long accessTokenExpiration = 900000L;

        /**
         * JWT refresh token expiration time in milliseconds (default: 7 days)
         */
        private long refreshTokenExpiration = 604800000L;
    }

    /**
     * Controller configuration properties
     */
    @Getter
    @Setter
    public static class Controllers {
        private Controller auth = new Controller();
        private Controller user = new Controller();

        @Getter
        @Setter
        public static class Controller {
            private boolean enabled = true;
        }
    }

    /**
     * Password policy configuration properties
     */
    @Getter
    @Setter
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
     * Refresh token configuration properties
     */
    @Getter
    @Setter
    public static class RefreshTokens {
        private boolean enabled = true;

        /**
         * Maximum number of refresh tokens per user (0 = unlimited)
         */
        @Min(0)
        private int maxTokensPerUser = 5;

        private boolean rotateOnRefresh = true;

        @Min(60000) // 1 minute
        private long cleanupInterval = 3600000L; // default 1 hour

        private boolean autoCleanup = true;

    }

    /**
     * Refresh token repository configuration properties
     */
    @Getter
    @Setter
    public static class Repositories {
        /**
         * Repository type for refresh tokens
         */
        private RepositoryType type = RepositoryType.JPA;

        /**
         * Database-specific settings for refresh tokens
         */
        private Database database = new Database();
    }

    /**
     * Database configuration properties
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
     * Rate limiter configuration properties
     */
    @Getter
    @Setter
    public static class RateLimiter {
        private boolean enabled = true;
        private StorageType type = StorageType.MEMORY;
        private int maxRequests = 150;
        private long timeWindowMs = 60000L;
    }

    /**
     * Token blocklist configuration properties
     */
    @Getter
    @Setter
    public static class TokenBlocklist {
        private boolean enabled = true;
        private StorageType type = StorageType.MEMORY;
    }

    /**
     * Redis configuration properties
     */
    @Getter
    @Setter
    public static class Redis {
        private String host = "localhost";
        private int port = 6379;
        private String password;
        private int database = 0;
    }

    /**
     * Cookie configuration properties
     */
    @Getter
    @Setter
    public static class Cookies {
        private AccessCookie access = new AccessCookie();
        private RefreshCookie refresh = new RefreshCookie();

        /**
         * Access token cookie configuration
         */
        @Getter
        @Setter
        public static class AccessCookie {
            private boolean secure = true;
            private boolean httpOnly = true;
            private SameSitePolicy sameSite = SameSitePolicy.STRICT;
            private String path = "/";
        }

        /**
         * Refresh token cookie configuration
         */
        @Getter
        @Setter
        public static class RefreshCookie {
            private boolean secure = true;
            private boolean httpOnly = true;
            private SameSitePolicy sameSite = SameSitePolicy.STRICT;
            private String path = "/api/auth/refresh";
        }
    }
}