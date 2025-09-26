package com.ricardo.auth.ratelimiter;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.RateLimiter;
import com.ricardo.auth.service.PasswordResetServiceImpl;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The type Redis rate limiter.
 */
@Component
@ConditionalOnClass(name = "org.springframework.data.redis.core.RedisTemplate")
@ConditionalOnProperty(prefix = "ricardo.auth.rate-limiter", name = "type", havingValue = "redis")
@Slf4j
public class RedisRateLimiter implements RateLimiter {

    private static final String RATE_LIMIT_KEY_PREFIX = "ricardo:auth:rate-limit:";


    private final RedisTemplate<String, String> redisTemplate;
    @Getter
    private final AtomicInteger maxRequests;
    @Getter
    private final AtomicLong windowMillis;
    private final boolean enabled;
    private final AtomicInteger ttlSeconds; // make TTL dynamic with settings changes

    /**
     * Instantiates a new Redis rate limiter.
     *
     * @param redisTemplate the redis template
     * @param properties    the properties
     */
    public RedisRateLimiter(RedisTemplate<String, String> redisTemplate,
                            AuthProperties properties) {
        this.redisTemplate = redisTemplate;
        this.maxRequests = new AtomicInteger(properties.getRateLimiter().getMaxRequests());
        this.windowMillis = new AtomicLong(properties.getRateLimiter().getTimeWindowMs());
        this.enabled = properties.getRateLimiter().isEnabled();
        this.ttlSeconds = new AtomicInteger(toTtlSeconds(this.windowMillis.get()));
    }

    @Override
    public void changeSettings(int maxRequests, long windowMillis) {
        if (maxRequests <= 0) {
            throw new IllegalArgumentException("maxRequests must be positive");
        }
        if (windowMillis <= 0) {
            throw new IllegalArgumentException("windowMillis must be positive");
        }
        this.maxRequests.set(maxRequests);
        this.windowMillis.set(windowMillis);
        this.ttlSeconds.set(toTtlSeconds(windowMillis));
    }

    private static int toTtlSeconds(long windowMillis) {
        // Round up so we don't expire too early
        return (int) Math.ceil(windowMillis / 1000.0);
    }

    /**
     * Creates a Redis key with the rate limiting prefix
     *
     * @param key the original key
     * @return the prefixed key for Redis storage
     */
    private String createRedisKey(String key) {
        return RATE_LIMIT_KEY_PREFIX + key;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public boolean allowRequest(String key) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }

        if (!enabled) {
            return true; // short-circuit when disabled
        }

        try {
            Long currentCount = redisTemplate.execute((RedisCallback<Long>) connection -> {
                String redisKey = createRedisKey(key);
                byte[] redisKeyBytes = redisKey.getBytes();

                // Atomic increment
                Long count = connection.incr(redisKeyBytes);

                // Set TTL only on first request to avoid resetting the window
                if (count == 1) {
                    connection.expire(redisKeyBytes, ttlSeconds.get());
                }
                return count;
            });

            boolean allowed = currentCount != null && currentCount <= maxRequests.get();

            if (!log.isDebugEnabled()) {
                return allowed;
            }

            return allowed;

        } catch (Exception e) {
            log.error("Redis rate limiter error for key '{}': {}", key, e.getMessage());
            log.info("Redis is down at time {}, so we are allowing the request", Instant.now());
            // Fail open - allow request when Redis is down
            return true;
        }
    }

    @Override
    public void clearAll() {
        try {
            redisTemplate.execute((RedisCallback<Void>) connection -> {
                // Limpa chaves com prefixo completo (incluindo RATE_LIMIT_KEY_PREFIX)
                clearPattern(connection, (RATE_LIMIT_KEY_PREFIX + "*").getBytes());
                return null;
            });
        } catch (Exception e) {
            log.error("Error clearing rate limiting data from Redis: {}", e.getMessage());
        }
    }


    private void clearPattern(RedisConnection connection, byte[] pattern) {
        var passwordResetCompleteKeys = connection.keys(pattern);

        if (!passwordResetCompleteKeys.isEmpty()) {
            connection.del(passwordResetCompleteKeys.toArray(new byte[0][]));
            log.info("Cleared {} password reset keys from Redis with prefix '{}'",
                    passwordResetCompleteKeys.size(), PasswordResetServiceImpl.PASSWORD_RESET_KEY_PREFIX);
        } else {
            log.info("No rate limiting keys found with prefix '{}'", PasswordResetServiceImpl.PASSWORD_RESET_KEY_PREFIX);
        }
    }
}
