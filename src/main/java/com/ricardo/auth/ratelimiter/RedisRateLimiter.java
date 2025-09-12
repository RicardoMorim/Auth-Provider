package com.ricardo.auth.ratelimiter;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.RateLimiter;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

@Component
@ConditionalOnClass(name = "org.springframework.data.redis.core.RedisTemplate")
@ConditionalOnProperty(prefix = "ricardo.auth.rate-limiter", name = "type", havingValue = "redis")
@Slf4j
public class RedisRateLimiter implements RateLimiter {

    private final RedisTemplate<String, String> redisTemplate;
    @Getter
    private final AtomicInteger maxRequests;
    @Getter
    private final AtomicLong windowMillis;
    private final boolean enabled;
    private final AtomicInteger ttlSeconds; // make TTL dynamic with settings changes

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

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public boolean allowRequest(String key) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }

        log.info("RateLimiter settings - enabled: {}, maxRequests: {}, windowMillis: {}, ttlSeconds: {}",
                enabled, maxRequests.get(), windowMillis.get(), ttlSeconds.get());

        if (!enabled) {
            return true; // short-circuit when disabled
        }
        log.info("Checking rate limit for key '{}'", key);

        try {
            Long currentCount = redisTemplate.execute((RedisCallback<Long>) connection -> {
                byte[] redisKey = key.getBytes();

                // Atomic increment
                Long count = connection.incr(redisKey);

                // Set TTL only on first request to avoid resetting the window
                if (count == 1) {
                    connection.expire(redisKey, ttlSeconds.get());
                }
                log.info("Current count for key '{}': {}", key, count);
                return count;
            });

            boolean allowed = currentCount != null && currentCount <= maxRequests.get();

            if (!log.isDebugEnabled()){
                return allowed;
            }

            if (allowed) {
                log.info("Request allowed for key '{}'. Current count: {}", key, currentCount);
            } else {
                log.warn("Rate limit exceeded for key '{}'. Current count: {}", key, currentCount);
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
                connection.flushDb();
                return null;
            });
            log.info("Cleared all rate limiting data from Redis");
        } catch (Exception e) {
            log.error("Error clearing rate limiting data from Redis: {}", e.getMessage());
        }
    }
}
