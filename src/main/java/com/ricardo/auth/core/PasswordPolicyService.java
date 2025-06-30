package com.ricardo.auth.core;

/**
 * The interface Password policy service.
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 */
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
