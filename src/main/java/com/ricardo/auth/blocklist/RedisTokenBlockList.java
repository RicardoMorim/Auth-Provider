package com.ricardo.auth.blocklist;

import com.ricardo.auth.core.TokenBlocklist;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * The type Redis token block list.
 */
@Component
@ConditionalOnProperty(prefix = "ricardo.auth.blocklist", name = "type", havingValue = "REDIS")
public class RedisTokenBlockList implements TokenBlocklist {

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
                "revoked:" + token,
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
        return redisTemplate.hasKey("revoked:" + token);
    }
}