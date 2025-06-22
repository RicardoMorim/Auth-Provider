package com.ricardo.auth.domain;

import com.ricardo.auth.core.Role;
import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Entity
@Table(name = "users")
public class User implements AuthUser<AppRole> {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Version
    private Long version;

    @Embedded
    private Username username;

    @Embedded
    @AttributeOverride(name = "email", column = @Column(unique = true, nullable = false))
    private Email email;

    @Embedded
    private Password password;

    @ElementCollection(targetClass = Role.class, fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "role")
    private Set<AppRole> roles;

    protected User() {
    }

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

    @Override
    public String getEmail() {
        return email.getEmail();
    }

    @Override
    public void setEmail(String email) {
        this.email = Email.valueOf(email);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getAuthority()))
                .collect(Collectors.toSet());
    }

    @Override
    public String getPassword() {
        return password.getHashed();
    }

    @Override
    public void setPassword(String hashedPassword) {
        this.password = Password.fromHash(hashedPassword);
    }

    @Override
    public String getUsername() {
        return username.getUsername();
    }

    @Override
    public void setUsername(String username) {
        this.username = Username.valueOf(username);
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

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
}