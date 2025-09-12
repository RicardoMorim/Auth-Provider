package com.ricardo.auth.domain.domainevents.enums;

public enum AuthenticationFailedReason {
    INVALID_CREDENTIALS,
    USER_NOT_FOUND,
    ACCOUNT_LOCKED,
    ACCOUNT_DISABLED,
    PASSWORD_EXPIRED,
    UNKNOWN_ERROR
}
