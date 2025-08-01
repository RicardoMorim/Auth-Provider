package com.ricardo.auth.blocklist;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.TokenBlocklist;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The type In memory token blocklist.
 */
@Component
@ConditionalOnProperty(prefix = "ricardo.auth.blocklist", name = "type", havingValue = "MEMORY", matchIfMissing = true)
public class InMemoryTokenBlocklist implements TokenBlocklist {
    private final Map<String, Long> revokedTokens = new ConcurrentHashMap<>();
    private final long ttlMillis;

    /**
     * Instantiates a new In memory token blocklist.
     *
     * @param authProperties the auth properties
     */
    public InMemoryTokenBlocklist(AuthProperties authProperties) {
        this.ttlMillis = authProperties.getJwt().getAccessTokenExpiration();
    }

    @Override
    public void revoke(String token) {
        if (token == null || token.isEmpty()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
        revokedTokens.put(token, System.currentTimeMillis() + ttlMillis);
    }

    @Override
    public boolean isRevoked(String token) {
        if (token == null || token.isEmpty()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
        Long expiration = revokedTokens.get(token);
        if (expiration == null) return false;
        if (expiration < System.currentTimeMillis()) {
            revokedTokens.remove(token);
            return false;
        }
        return true;
    }

    /**
     * Cleanup expired tokens.
     */
    @Scheduled(fixedRate = 60000)
    public void cleanupExpiredTokens() {
        long now = System.currentTimeMillis();
        revokedTokens.entrySet().removeIf(entry -> entry.getValue() < now);
    }
}