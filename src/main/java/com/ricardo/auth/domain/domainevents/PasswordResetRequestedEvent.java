package com.ricardo.auth.domain.domainevents;

import java.util.Objects;

public record PasswordResetRequestedEvent(String username, String email) {

  public PasswordResetRequestedEvent {
    Objects.requireNonNull(username, "username must not be null");
    Objects.requireNonNull(email, "email must not be null");
    if (username.isBlank()) throw new IllegalArgumentException("username must not be blank");
    if (email.isBlank()) throw new IllegalArgumentException("email must not be blank");
  }

  @Override
  public String toString() {
    return "PasswordResetRequestedEvent[username=%s,email=%s]"
        .formatted(username, maskEmail(email));
  }

  private static String maskEmail(String email) {
    int at = email.indexOf('@');
    if (at <= 1) return "***";
    String local = email.substring(0, at);
    String domain = email.substring(at + 1);
    String maskedLocal = local.charAt(0) + "***" + local.charAt(local.length() - 1);
    return maskedLocal + "@" + domain;
  }
}