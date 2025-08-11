package com.ricardo.auth.domain.refreshtoken;


import com.ricardo.auth.domain.exceptions.TokenExpiredException;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * The type Refresh token.
 */
@Entity
@Getter
@Table(name = "refresh_tokens", indexes = {
        @Index(name = "idx_refresh_token_token", columnList = "token"),
        @Index(name = "idx_refresh_token_user_email", columnList = "user_email"),
        @Index(name = "idx_refresh_token_expiry_date", columnList = "expiry_date"),
        @Index(name = "idx_refresh_token_user_created", columnList = "user_email, created_at"),
        @Index(name = "idx_refresh_token_revoked", columnList = "revoked")
})
@Data
@Builder
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class RefreshToken {

    @Version
    @Setter
    private Long version;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(columnDefinition = "uuid")
    private UUID id;

    @Column(unique = true, nullable = false, length = 1000)
    private String token;
    // store the email. works with ANY AuthUser implementation. no need for generic class as this handles it much simpler
    @Column(name = "user_email", nullable = false)
    private String userEmail;
    @Column(nullable = false)
    private Instant expiryDate;
    @Setter
    @Column(nullable = false)
    private boolean revoked;
    @Column(name = "created_at", nullable = false)
    @Setter
    private Instant createdAt;

    /**
     * Instantiates a new Refresh token.
     */
    protected RefreshToken() {
    }

    /**
     * Instantiates a new Refresh token.
     *
     * @param refreshToken the refresh token
     * @param email        the email
     * @param expiration   the expiration
     */
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
        this.createdAt = Instant.now();
    }

    /**
     * On create.
     */
    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }

    @Override
    public String toString() {
        return "RefreshToken{" +
                "refreshToken='" + token + '\'' +
                "is revoked:" +
                isRevoked() +
                '}';
    }

    /**
     * Is expired boolean.
     *
     * @return the boolean
     */
    public boolean isExpired() {
        return Instant.now().isAfter(expiryDate);
    }

    /**
     * Is revoked boolean.
     *
     * @return the boolean
     */
    public boolean isRevoked() {
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
     */
    @SuppressWarnings("unused")
    public void setId(UUID id) {
        this.id = id;
    }
}
