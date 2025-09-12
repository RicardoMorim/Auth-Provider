package com.ricardo.auth.core;

/**
 * The interface Rate limiter.
 */
public interface RateLimiter {
    /**
     * Allow request boolean.
     *
     * @param key the key
     * @return the boolean
     */
    boolean allowRequest(String key);

    /**
     * Is enabled boolean.
     *
     * @return the boolean
     */
    boolean isEnabled();

    /**
     * Change settings.
     *
     * @param maxRequests the max requests
     * @param windowMillis the window millis
     */
    void changeSettings(int maxRequests, long windowMillis);

    /**
     * Clear all.
     */
    void clearAll();
}
