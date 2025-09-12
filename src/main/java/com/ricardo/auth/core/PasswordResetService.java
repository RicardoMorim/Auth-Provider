package com.ricardo.auth.core;

public interface PasswordResetService {
    void requestPasswordReset(String email);
    void completePasswordReset(String token, String newPassword);
    boolean validatePasswordResetToken(String token);
}