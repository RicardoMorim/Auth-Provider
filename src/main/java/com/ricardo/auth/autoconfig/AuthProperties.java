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
@Setter
@Getter
@ConfigurationProperties(prefix = "ricardo.auth")
public class AuthProperties {

    // Root level getters and setters
    /**
     * Rate limiter configuration
     * -- GETTER --
     * Gets rate limiter.
     * <p>
     * <p>
     * -- SETTER --
     * Sets rate limiter.
     *
     * @return the rate limiter
     * @param rateLimiter the rate limiter
     */
    RateLimiter rateLimiter = new RateLimiter();
    /**
     * The Token blocklist.
     */
    TokenBlocklist tokenBlocklist = new TokenBlocklist();
    /**
     * Redis configuration
     * -- GETTER --
     * Gets redis.
     * <p>
     * <p>
     * -- SETTER --
     * Sets redis.
     *
     * @return the redis
     * @param redis the redis
     */
    Redis redis = new Redis();
    /**
     * The Cookies.
     */
    Cookies cookies = new Cookies();
    /**
     * Whether auth is enabled
     * -- GETTER --
     * Is enabled boolean.
     * <p>
     * <p>
     * -- SETTER --
     * Sets enabled.
     *
     * @return the boolean
     * @param enabled the enabled
     */
    private boolean enabled = true;
    /**
     * JWT configuration
     * -- GETTER --
     * Gets jwt.
     * <p>
     * <p>
     * -- SETTER --
     * Sets jwt.
     *
     * @return the jwt
     * @param jwt the jwt
     */
    private Jwt jwt = new Jwt();
    /**
     * Controller configuration
     * -- GETTER --
     * Gets controllers.
     * <p>
     * <p>
     * -- SETTER --
     * Sets controllers.
     *
     * @return the controllers
     * @param controllers the controllers
     */
    private Controllers controllers = new Controllers();
    /**
     * Password policy configuration
     * -- GETTER --
     * Gets password policy.
     * <p>
     * <p>
     * -- SETTER --
     * Sets password policy.
     *
     * @return the password policy
     * @param passwordPolicy the password policy
     */
    private PasswordPolicy passwordPolicy = new PasswordPolicy();
    /**
     * Refresh token configuration
     * -- GETTER --
     * Gets refresh tokens.
     * <p>
     * <p>
     * -- SETTER --
     * Sets refresh tokens.
     *
     * @return the refresh tokens
     * @param refreshTokens the refresh tokens
     */
    private RefreshTokens refreshTokens = new RefreshTokens();
    private boolean redirectHttps = true;

    /**
     * The enum Refresh token repository type.
     */
    public enum RefreshTokenRepositoryType {
        /**
         * Jpa refresh token repository type.
         */
        JPA("jpa"),
        /**
         * Postgresql refresh token repository type.
         */
        POSTGRESQL("postgresql");

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
     * The type Cookies.
     */
    @Getter
    @Setter
    public static class Cookies {
        private AccessCookie access = new AccessCookie();
        private RefreshCookie refresh = new RefreshCookie();

        /**
         * The type Access cookie.
         */
        @Getter
        @Setter
        public static class AccessCookie {
            private boolean secure = true;
            private boolean httpOnly = true;
            private String sameSite = "Strict"; // Options: Strict, Lax, None
            private String path = "/";
        }

        /**
         * The type Refresh cookie.
         */
        @Getter
        @Setter
        public static class RefreshCookie {
            private boolean secure = true;
            private boolean httpOnly = true;
            private String sameSite = "Strict"; // Options: Strict, Lax, None
            private String path = "/api/auth/refresh";
        }
    }

    /**
     * The type Redis.
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
     * The type Rate limiter.
     */
    @Getter
    @Setter
    public static class RateLimiter {
        private boolean enabled = true;
        private String type = "memory"; // memory|redis
        private int maxRequests = 100;
        private long timeWindowMs = 60000L;
    }

    /**
     * The type Token blocklist.
     */
    @Getter
    @Setter
    public static class TokenBlocklist {
        private boolean enabled = true;
        private String type = "memory"; // memory|redis
    }

    /**
     * The type Refresh tokens.
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

}