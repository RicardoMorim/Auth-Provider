package com.ricardo.auth.autoconfig;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for Ricardo Auth Starter
 * This class enables IDE auto-completion on the application.properties file and allows users to configure the settings without needing to write code.
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
     * The type Jwt.
     */
    public static class Jwt {
        /**
         * JWT secret key (Base64 encoded) - REQUIRED
         */
        private String secret;

        /**
         * JWT expiration time in milliseconds (default: 7 days)
         */
        private long expiration = 604800000L;

        /**
         * Gets secret.
         *
         * @return the secret
         */
        public String getSecret() { return secret; }

        /**
         * Sets secret.
         *
         * @param secret the secret
         */
        public void setSecret(String secret) { this.secret = secret; }

        /**
         * Gets expiration.
         *
         * @return the expiration
         */
        public long getExpiration() { return expiration; }

        /**
         * Sets expiration.
         *
         * @param expiration the expiration
         */
        public void setExpiration(long expiration) { this.expiration = expiration; }
    }

    /**
     * The type Controllers.
     */
    public static class Controllers {
        private Controller auth = new Controller();
        private Controller user = new Controller();

        /**
         * The type Controller.
         */
        public static class Controller {
            private boolean enabled = true;

            /**
             * Is enabled boolean.
             *
             * @return the boolean
             */
            public boolean isEnabled() { return enabled; }

            /**
             * Sets enabled.
             *
             * @param enabled the enabled
             */
            public void setEnabled(boolean enabled) { this.enabled = enabled; }
        }

        /**
         * Gets auth.
         *
         * @return the auth
         */
        public Controller getAuth() { return auth; }

        /**
         * Sets auth.
         *
         * @param auth the auth
         */
        public void setAuth(Controller auth) { this.auth = auth; }

        /**
         * Gets user.
         *
         * @return the user
         */
        public Controller getUser() { return user; }

        /**
         * Sets user.
         *
         * @param user the user
         */
        public void setUser(Controller user) { this.user = user; }
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
}