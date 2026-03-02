package com.ricardo.auth.blocklist;

import com.ricardo.auth.core.TokenBlocklist;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/**
 * Redis-backed token blocklist implementation.
 */
public class RedisTokenBlockList implements TokenBlocklist {

    private static final String REVOKED_PREFIX = "revoked:";

    private final RedisTemplate<String, String> redisTemplate;
    private final long ttlMillis;

    /**
     * Instantiates a new Redis token block list.
     *
     * @param redisTemplate the redis template
     * @param ttlMillis     the ttl millis
     */
    public RedisTokenBlockList(RedisTemplate<String, String> redisTemplate,
                               @Value("${ricardo.auth.jwt.access-token-expiration}") long ttlMillis) {
        this.redisTemplate = redisTemplate;
        this.ttlMillis = ttlMillis;
    }

    @Override
    public void revoke(String token) {
        if (token == null || token.isEmpty()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
        redisTemplate.opsForValue().set(
                toRedisKey(token),
                "1",
                ttlMillis,
                TimeUnit.MILLISECONDS
        );
    }

    @Override
    public boolean isRevoked(String token) {
        if (token == null || token.isEmpty()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
        return redisTemplate.hasKey(toRedisKey(token));
    }

    private String toRedisKey(String token) {
        return REVOKED_PREFIX + hashToken(token);
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
}