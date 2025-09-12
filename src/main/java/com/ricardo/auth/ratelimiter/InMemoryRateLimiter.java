package com.ricardo.auth.ratelimiter;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.RateLimiter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.StampedLock;

/**
 * The type In memory rate limiter.
 */
@Component
@ConditionalOnProperty(prefix = "ricardo.auth.rate-limiter", name = "type", havingValue = "MEMORY", matchIfMissing = true)
public class InMemoryRateLimiter implements RateLimiter {

    private final AtomicInteger maxRequests;
    private final AtomicLong windowMillis;
    private final ConcurrentHashMap<String, RequestCounter> counters = new ConcurrentHashMap<>();
    private final StampedLock countersLock = new StampedLock();
    private final boolean enabled;

    /**
     * Instantiates a new In memory rate limiter.
     *
     * @param properties the properties
     */
    public InMemoryRateLimiter(AuthProperties properties) {
        this.maxRequests = new AtomicInteger();
        this.windowMillis = new AtomicLong();
        this.maxRequests.set(properties.getRateLimiter().getMaxRequests());
        this.windowMillis.set(properties.getRateLimiter().getTimeWindowMs());
        if (maxRequests.get() <= 0) {
            throw new IllegalArgumentException("maxRequests must be positive");
        }
        if (windowMillis.get() <= 0) {
            throw new IllegalArgumentException("windowMillis must be positive");
        }
        this.enabled = properties.getRateLimiter().isEnabled();
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
        long currentTime = System.currentTimeMillis();

        long readStamp = countersLock.readLock();
        try {
            RequestCounter counter = counters.computeIfAbsent(key, k -> new RequestCounter());

            StampedLock lock = counter.lock;
            long stamp = lock.writeLock();
            try {
                counter.cleanup(currentTime);
                if (counter.getCount() >= maxRequests.get()) {
                    return false;
                }
                counter.increment(currentTime);
                return true;
            } finally {
                lock.unlockWrite(stamp);
            }
        } finally {
            countersLock.unlockRead(readStamp);
        }
    }

    /**
     * Cleanup old entries.
     */
    @Scheduled(fixedRateString = "${ricardo.auth.rate-limiter.cleanup-interval:60000}")
    public void cleanupOldEntries() {
        long cutoff = System.currentTimeMillis() - windowMillis.get();
        long writeStamp = countersLock.writeLock();
        try {
            counters.entrySet().removeIf(entry ->
                    entry.getValue().getLastAccess() < cutoff
            );
        } finally {
            countersLock.unlockWrite(writeStamp);
        }
    }

    private class RequestCounter {
        private final ConcurrentHashMap<Long, AtomicInteger> timestamps = new ConcurrentHashMap<>();
        private final StampedLock lock = new StampedLock();
        private volatile long lastAccess = System.currentTimeMillis();

        /**
         * Cleanup.
         *
         * @param currentTime the current time
         */
        void cleanup(long currentTime) {
            long cutoff = currentTime - windowMillis.get();
            timestamps.keySet().removeIf(timestamp -> timestamp < cutoff);
        }

        /**
         * Gets count.
         *
         * @return the count
         */
        int getCount() {
            return timestamps.values().stream()
                    .mapToInt(AtomicInteger::get)
                    .sum();
        }

        /**
         * Increment.
         *
         * @param currentTime the current time
         */
        void increment(long currentTime) {
            long bucket = (currentTime / 1000) * 1000; // 1-second buckets
            timestamps.computeIfAbsent(bucket, k -> new AtomicInteger())
                    .incrementAndGet();
            lastAccess = currentTime;
        }

        /**
         * Gets last access.
         *
         * @return the last access
         */
        long getLastAccess() {
            return lastAccess;
        }
    }

    @Override
    public void clearAll() {
        long writeStamp = countersLock.writeLock();
        try {
            counters.clear();
        } finally {
            countersLock.unlockWrite(writeStamp);
        }
    }
}
