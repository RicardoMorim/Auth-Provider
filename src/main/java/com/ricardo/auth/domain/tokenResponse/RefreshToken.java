package com.ricardo.auth.domain.tokenResponse;


import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Getter
@Table(name="refresh_token")
public class RefreshToken {


    protected RefreshToken() {}

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String token;

    // store the email. works with ANY AuthUser implementation. no need for generic class as this handles it much simpler
    @Column(name = "user_email", nullable = false)
    private String userEmail;

    @Column(nullable = false)
    private Instant expiryDate;

    @Setter
    @Column(nullable = false)
    private boolean revoked = false;

    public RefreshToken(String refreshToken, String email, Instant expiration) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalArgumentException("Refresh token cannot be null or blank");
        }

        if (email == null || email.isEmpty()) {
            throw new IllegalArgumentException("User details cannot be null");
        }

        if (expiration == null || expiration.isBefore(Instant.now())) {
            throw new IllegalArgumentException("Expiration must be a future date");
        }

        this.token = refreshToken;
        this.userEmail = email;
        this.expiryDate = expiration;
    }

    @Override
    public String toString() {
        return "RefreshToken{" +
                "refreshToken='" + token + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RefreshToken)) return false;
        RefreshToken that = (RefreshToken) o;
        return token.equals(that.token);
    }

    @Override
    public int hashCode() {
        return token.hashCode();
    }
}
