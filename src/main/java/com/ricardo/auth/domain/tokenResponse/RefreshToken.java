package com.ricardo.auth.domain.tokenResponse;


import com.ricardo.auth.domain.exceptions.TokenExpiredException;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Getter
@Table(name="refresh_tokens")
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
    private boolean revoked;

    public RefreshToken(String refreshToken, String email, Instant expiration) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalArgumentException("Refresh token cannot be null or blank");
        }

        if (email == null || email.isEmpty()) {
            throw new IllegalArgumentException("User details cannot be null");
        }

        if (expiration == null || expiration.isBefore(Instant.now())) {
            throw new TokenExpiredException("Expiration must be a future date");
        }

        this.token = refreshToken;
        this.userEmail = email;
        this.expiryDate = expiration;
        this.revoked = false;
    }

    @Override
    public String toString() {
        return "RefreshToken{" +
                "refreshToken='" + token + '\'' +
                "is revoked:"+
                isRevoked()+
                '}';
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiryDate);
    }

    public boolean isRevoked(){
        return revoked;
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

    /**
     * Sets the ID of the refresh token.
     * THIS METHOD IS FOR POSTGRESQL ONLY.
     * JPA/HIBERNATE WILL SET THE ID AUTOMATICALLY.
     *
     * @param id the ID to set
    **/
    @SuppressWarnings("unused")
    public void setId(Long id) {
        this.id = id;
    }
}
