package com.ricardo.auth.ratelimiter;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.RateLimiter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * The type Redis rate limiter.
 */
@Component
@ConditionalOnClass(name = "org.springframework.data.redis.core.RedisTemplate")
@ConditionalOnProperty(prefix = "ricardo.auth.rate-limiter", name = "type", havingValue = "REDIS")
@Slf4j
public class RedisRateLimiter implements RateLimiter {

    private final RedisTemplate<String, String> redisTemplate;
    private final int maxRequests;
    private final long windowMillis;
    private final boolean enabled;
    private final int ttlSeconds;

    /**
     * Instantiates a new Redis rate limiter.
     *
     * @param redisTemplate the redis template
     * @param properties    the properties
     */
    public RedisRateLimiter(RedisTemplate<String, String> redisTemplate,
                            AuthProperties properties) {
        this.redisTemplate = redisTemplate;
        this.maxRequests = properties.getRateLimiter().getMaxRequests();
        this.windowMillis = properties.getRateLimiter().getTimeWindowMs();
        this.enabled = properties.getRateLimiter().isEnabled();
        // Round up to ensure we don't expire too early
        this.ttlSeconds = (int) Math.ceil(windowMillis / 1000.0);
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

        try {
            Long currentCount = redisTemplate.execute((RedisCallback<Long>) connection -> {
                byte[] redisKey = key.getBytes();

                // Atomic increment
                Long count = connection.incr(redisKey);

                // Set TTL only on first request to avoid resetting the window
                if (count == 1) {
                    connection.expire(redisKey, ttlSeconds);
                }

                return count;
            });

            boolean allowed = currentCount != null && currentCount <= maxRequests;

            if (log.isDebugEnabled()) {
                log.debug("Rate limit check for key '{}': count={}, max={}, allowed={}",
                        key, currentCount, maxRequests, allowed);
            }

            return allowed;

        } catch (Exception e) {
            log.error("Redis rate limiter error for key '{}': {}", key, e.getMessage());
            log.info("Redis is down at time {}, so we are allowing the request", Instant.now());
            // Fail open - allow request when Redis is down
            return true;
        }
    }
}