package com.ricardo.auth.domain.domainevents.enums;

/**
 * The enum Access denied reason.
 */
public enum AccessDeniedReason {
    /**
     * Missing token access denied reason.
     */
    MISSING_TOKEN,
    /**
     * Invalid token access denied reason.
     */
    INVALID_TOKEN,
    /**
     * Expired token access denied reason.
     */
    EXPIRED_TOKEN,
    /**
     * Insufficient permissions access denied reason.
     */
    INSUFFICIENT_PERMISSIONS,
    /**
     * Token revoked access denied reason.
     */
    TOKEN_REVOKED,
    /**
     * Rate limit exceeded access denied reason.
     */
    RATE_LIMIT_EXCEEDED,
    /**
     * Unknown error access denied reason.
     */
    UNKNOWN_ERROR
}
