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

    private String baseUrl = "http://localhost:8080";

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

    private Repository repository = new Repository();

    /**
     * Password reset configuration
     */
    private PasswordReset passwordReset = new PasswordReset();

    /**
     * Email configuration
     */
    private Email email = new Email();

    /**
     * Role management configuration
     */
    private RoleManagement roleManagement = new RoleManagement();

    /**
     * Repository types for refresh tokens
     */
    public enum RepositoryType {
        /**
         * Jpa repository type.
         */
        JPA("jpa"),
        /**
         * Postgresql repository type.
         */
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
        /**
         * Memory storage type.
         */
        MEMORY("memory"),
        /**
         * Redis storage type.
         */
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
        /**
         * Strict same site policy.
         */
        STRICT("Strict"),
        /**
         * Lax same site policy.
         */
        LAX("Lax"),
        /**
         * None same site policy.
         */
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
    public static class Repository {
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
        private String passwordResetTokensTable = "password_reset_tokens";
        private String schema;
        private String url;
        private String driverClassName;
        private String username;
        private String password;
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

    /**
     * Password reset configuration properties
     */
    @Getter
    @Setter
    public static class PasswordReset {
        private boolean enabled = true;
        private int tokenExpiryHours = 1;
        private int maxAttempts = 3;
        private int timeWindowMs = 3600000;
        private boolean enableCleanup = true;
        private int cleanupIntervalHours = 24;
        private int tokenLength = 32;
        private boolean requireHttps = true;
    }

    /**
     * Email configuration properties
     */
    @Getter
    @Setter
    public static class Email {
        private String fromAddress = "noreply@example.com";
        private String password; // YOU MAY USE A ENV VARIABLE INSTEAD OF PROPERTIES FOR THIS ONE
        private String host = "smtp.gmail.com";
        private int port = 587;
        private String fromName = "Auth Service";
        private String resetSubject = "Password Reset Request";
        private String resetTemplate = "default";
    }

    /**
     * Role management configuration properties
     */
    @Getter
    @Setter
    public static class RoleManagement {
        private boolean enableRoleEvents = true;
        private boolean requireAdminForRoleChanges = true;
        private boolean allowSelfRoleModification = false;
    }
}