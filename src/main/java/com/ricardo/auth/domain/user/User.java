package com.ricardo.auth.domain.user;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import jakarta.persistence.*;
import org.hibernate.annotations.BatchSize;
import org.hibernate.annotations.UuidGenerator;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * The type User.
 */
@Table(
        name = "users",
        indexes = {
                @Index(name = "idx_users_email", columnList = "email"),
                @Index(name = "idx_users_username", columnList = "username")
        }
)
@Entity
public class User implements AuthUser<UUID, AppRole> {

    @Id
    @GeneratedValue
    @UuidGenerator
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Version
    private Long version;

    @Embedded
    @AttributeOverride(name = "username", column = @Column(name = "username", unique = true, nullable = false))
    private Username username;

    @Embedded
    @AttributeOverride(name = "email", column = @Column(name = "email", unique = true, nullable = false))
    private Email email;

    @Embedded
    private Password password;

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    @CollectionTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            foreignKey = @ForeignKey(name = "fk_user_roles_user_id")
    )
    @Column(name = "role")
    @BatchSize(size = 25)
    @JsonSerialize(as = java.util.Set.class)
    @JsonDeserialize(as = java.util.HashSet.class)
    private Set<AppRole> roles = new HashSet<>();

    private Instant createdAt;
    private Instant updatedAt;

    private boolean accountNonExpired = true;
    private boolean accountNonLocked = true;
    private boolean credentialsNonExpired = true;

    private boolean enabled = true;

    /**
     * Instantiates a new User.
     */
    protected User() {
    }

    /**
     * Instantiates a new User.
     *
     * @param username the username
     * @param email    the email
     * @param password the password
     */
    public User(Username username, Email email, Password password) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
        this.roles = new HashSet<>(); // don't add any roles, let the service handle it so any custom role can be added
    }

    @Override
    public UUID getId() {
        return id;
    }


    @Override
    public String getEmail() {
        return email.getEmail();
    }

    @Override
    public void setEmail(String email) {
        this.email = Email.valueOf(email);
    }

    /**
     * Gets authorities.
     *
     * @return the authorities
     */
    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getAuthority()))
                .collect(Collectors.toSet());
    }


    /**
     * Gets version.
     *
     * @return the version
     */
    @Override
    public Long getVersion() {
        return version;
    }

    /**
     * Sets version.
     *
     * @param version the version
     */
    @Override
    public void setVersion(Long version) {
        this.version = version;
    }

    /**
     * Gets password.
     *
     * @return the password
     */
    @Override
    public String getPassword() {
        return password.getHashed();
    }

    @Override
    public void setPassword(String hashedPassword) {
        this.password = Password.fromHash(hashedPassword);
    }

    /**
     * Gets username.
     *
     * @return the username
     */
    @Override
    public String getUsername() {
        return username.getUsername();
    }

    @Override
    public void setUsername(String username) {
        this.username = Username.valueOf(username);
    }

    /**
     * Is account non expired boolean.
     *
     * @return the boolean
     */
    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    /**
     * Is account non locked boolean.
     *
     * @return the boolean
     */
    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    /**
     * Is credentials non expired boolean.
     *
     * @return the boolean
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    /**
     * Is enabled boolean.
     *
     * @return the boolean
     */
    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public Set<AppRole> getRoles() {
        return roles;
    }

    @Override
    public void addRole(AppRole role) {
        if (role != null) {
            this.roles.add(role);
        }
    }

    @Override
    public void removeRole(AppRole role) {
        if (role != null) {
            this.roles.remove(role);
        }
    }


    @Override
    public void setId(UUID id) {
        if (id != null) {
            this.id = id;
        } else {
            throw new IllegalArgumentException("ID cannot be null");
        }
    }


    @Override
    public void setRoles(Set<AppRole> roles) {
        if (roles == null || roles.isEmpty()) {
            this.roles = new HashSet<>();
            return;
        }
        // Defensive copy and null-filter
        this.roles = roles.stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(HashSet::new));
    }

    @Override
    public Instant getCreatedAt() {
        return createdAt;
    }

    @Override
    public Instant getUpdatedAt() {
        return updatedAt;
    }

    @Override
    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt != null ? createdAt : Instant.now();
    }

    @Override
    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt != null ? updatedAt : Instant.now();
    }
}