package com.ricardo.auth.core;

import java.util.List;

/**
 * The interface Authenticated user.
 */
public interface AuthenticatedUser {
    /**
     * Gets email.
     *
     * @return the email
     */
    String getName();

    /**
     * Gets roles.
     *
     * @return the roles
     */
    List<String> getRoles();
}
