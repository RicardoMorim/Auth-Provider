package com.ricardo.auth.blocklist;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.TokenBlocklist;
import org.springframework.scheduling.annotation.Scheduled;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The type In memory token blocklist.
 */
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
        revokedTokens.put(toBlocklistKey(token), System.currentTimeMillis() + ttlMillis);
    }

    @Override
    public boolean isRevoked(String token) {
        if (token == null || token.isEmpty()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
        String tokenKey = toBlocklistKey(token);
        Long expiration = revokedTokens.get(tokenKey);
        if (expiration == null) return false;
        if (expiration < System.currentTimeMillis()) {
            revokedTokens.remove(tokenKey);
            return false;
        }
        return true;
    }

    private String toBlocklistKey(String token) {
        return hashToken(token);
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 algorithm is not available", exception);
        }
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