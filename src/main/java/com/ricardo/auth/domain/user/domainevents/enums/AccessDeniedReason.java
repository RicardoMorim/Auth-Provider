package com.ricardo.auth.domain.user.domainevents.enums;

public enum AccessDeniedReason {
    MISSING_TOKEN,
    INVALID_TOKEN,
    EXPIRED_TOKEN,
    INSUFFICIENT_PERMISSIONS,
    TOKEN_REVOKED,
    RATE_LIMIT_EXCEEDED,
    UNKNOWN_ERROR
}
