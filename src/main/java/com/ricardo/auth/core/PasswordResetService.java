package com.ricardo.auth.core;

/**
 * The interface Password reset service.
 */
public interface PasswordResetService {
    /**
     * Request password reset.
     *
     * @param email the email
     */
    void requestPasswordReset(String email);

    /**
     * Complete password reset.
     *
     * @param token       the token
     * @param newPassword the new password
     */
    void completePasswordReset(String token, String newPassword);

    /**
     * Validate password reset token boolean.
     *
     * @param token the token
     * @return the boolean
     */
    boolean validatePasswordResetToken(String token);
}