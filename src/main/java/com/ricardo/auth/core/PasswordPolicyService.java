package com.ricardo.auth.core;

import java.util.Set;

public interface PasswordPolicyService {

    /**
     * Validates the password against the policy.
     *
     * @param password the password to validate
     * @return true if the password meets the policy requirements, false otherwise
     */
    boolean validatePassword(String password);

    /**
     * Generates a secure random password.
     *
     * @return a secure random password
     */
    String generateSecurePassword();
}
