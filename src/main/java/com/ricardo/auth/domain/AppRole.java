package com.ricardo.auth.domain;

import com.ricardo.auth.core.Role;


/**
 * Enum representing the application roles.
 * Implements the Role interface to provide role authority.
 * This enum defines two roles: USER and ADMIN.
 * The authority for each role is prefixed with "ROLE_"
 */
public enum AppRole implements Role {
    /**
     * User app role.
     */
    USER,
    /**
     * Admin app role.
     */
    ADMIN,
    /**
     * Vip app role.
     */
    VIP;

    @Override
    public String getAuthority() {
        return "ROLE_" + this.name();
    }
}