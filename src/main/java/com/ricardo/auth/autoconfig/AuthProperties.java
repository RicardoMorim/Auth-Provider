package com.ricardo.auth.autoconfig;

import org.hibernate.cfg.Environment;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for Ricardo Auth Starter
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
     * The type Jwt.
     */
    public static class Jwt {
        /**
         * JWT secret key (Base64 encoded)
         */
        @Value("${jwt.secret}")
        private String secret;

        /**
         * JWT expiration time in milliseconds
         */
        @Value("${jwt.expiration:604800000}") // 7 dias em ms
        private long expiration;

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
}