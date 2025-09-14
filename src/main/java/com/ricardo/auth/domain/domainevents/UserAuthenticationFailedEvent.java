package com.ricardo.auth.domain.domainevents;

import com.ricardo.auth.domain.domainevents.enums.AuthenticationFailedReason;

public record UserAuthenticationFailedEvent(String email, AuthenticationFailedReason reason) {
  public UserAuthenticationFailedEvent {
    java.util.Objects.requireNonNull(email, "email must not be null");
    java.util.Objects.requireNonNull(reason, "reason must not be null");
  }
  @Override public String toString() {
    return "UserAuthenticationFailedEvent[email=%s, reason=%s]"
        .formatted(maskEmail(email), reason);
  }
  private static String maskEmail(String e) {
    if (e == null) return null;
    int at = e.indexOf('@');
    return at >= 0 ? "***" + e.substring(at) : "***";
  }
}