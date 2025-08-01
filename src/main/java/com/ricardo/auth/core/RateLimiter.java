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
}
