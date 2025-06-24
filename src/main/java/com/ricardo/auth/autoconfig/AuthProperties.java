package com.ricardo.auth.autoconfig;

import org.hibernate.cfg.Environment;
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

    public static class Jwt {
        /**
         * JWT secret key (Base64 encoded)
         */
        private String secret = Environment.getProperties().getProperty("jwt.secret");

        /**
         * JWT expiration time in milliseconds
         */
        private long expiration = 604800000L; // 7 days

        // Getters and setters
        public String getSecret() { return secret; }
        public void setSecret(String secret) { this.secret = secret; }
        public long getExpiration() { return expiration; }
        public void setExpiration(long expiration) { this.expiration = expiration; }
    }

    public static class Controllers {
        private Controller auth = new Controller();
        private Controller user = new Controller();

        public static class Controller {
            private boolean enabled = true;

            public boolean isEnabled() { return enabled; }
            public void setEnabled(boolean enabled) { this.enabled = enabled; }
        }

        public Controller getAuth() { return auth; }
        public void setAuth(Controller auth) { this.auth = auth; }
        public Controller getUser() { return user; }
        public void setUser(Controller user) { this.user = user; }
    }

    // Main getters and setters
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public Jwt getJwt() { return jwt; }
    public void setJwt(Jwt jwt) { this.jwt = jwt; }
    public Controllers getControllers() { return controllers; }
    public void setControllers(Controllers controllers) { this.controllers = controllers; }
}