package com.ricardo.auth.domain.user;

import jakarta.persistence.*;
import org.hibernate.annotations.BatchSize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The type User.
 */
@Entity
@Table(name = "users")
public class User implements AuthUser<AppRole> {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Version
    private Long version;

    @Embedded
    @AttributeOverride(name = "username", column = @Column(unique = true, nullable = false))
    private Username username;

    @Embedded
    @AttributeOverride(name = "email", column = @Column(unique = true, nullable = false))
    private Email email;

    @Embedded
    private Password password;

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    @BatchSize(size = 25)  // ✅ Add this to batch fetch roles
    private Set<AppRole> roles = new HashSet<>();

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
        this.roles = new HashSet<>(); // dont add any roles, let the service handle it so any custom role can be added
    }

    @Override
    public Long getId() {
        return id;
    }

    /**
     * Sets id.
     *
     * @param id the id
     */
    public void setId(Long id) {
        this.id = id;
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
    public Long getVersion() {
        return version;
    }

    /**
     * Sets version.
     *
     * @param version the version
     */
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
        return true;
    }

    /**
     * Is account non locked boolean.
     *
     * @return the boolean
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * Is credentials non expired boolean.
     *
     * @return the boolean
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * Is enabled boolean.
     *
     * @return the boolean
     */
    @Override
    public boolean isEnabled() {
        return true;
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
}