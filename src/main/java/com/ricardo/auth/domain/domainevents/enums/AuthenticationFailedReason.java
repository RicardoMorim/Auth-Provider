package com.ricardo.auth.domain.domainevents.enums;

/**
 * The enum Authentication failed reason.
 */
public enum AuthenticationFailedReason {
    /**
     * Invalid credentials authentication failed reason.
     */
    INVALID_CREDENTIALS,
    /**
     * User not found authentication failed reason.
     */
    USER_NOT_FOUND,
    /**
     * Account locked authentication failed reason.
     */
    ACCOUNT_LOCKED,
    /**
     * Account disabled authentication failed reason.
     */
    ACCOUNT_DISABLED,
    /**
     * Password expired authentication failed reason.
     */
    PASSWORD_EXPIRED,
    /**
     * Unknown error authentication failed reason.
     */
    UNKNOWN_ERROR
}
