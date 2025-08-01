package com.ricardo.auth.core;

/**
 * The interface Token blocklist.
 */
public interface TokenBlocklist {
    /**
     * Revoke.
     *
     * @param token the token
     */
    void revoke(String token);

    /**
     * Is revoked boolean.
     *
     * @param token the token
     * @return the boolean
     */
    boolean isRevoked(String token);
}
