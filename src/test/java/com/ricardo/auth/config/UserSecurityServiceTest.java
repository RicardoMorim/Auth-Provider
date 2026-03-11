package com.ricardo.auth.config;

import com.ricardo.auth.core.Role;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.helper.IdConverter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;

import java.time.Instant;
import java.util.Collection;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserSecurityServiceTest {

    @Mock
    private UserService<TestUser, TestRole, UUID> userService;

    @Mock
    private IdConverter<UUID> idConverter;

    private UserSecurityService<TestUser, TestRole, UUID> userSecurityService;

    @BeforeEach
    void setUp() {
        userSecurityService = new UserSecurityService<>(userService, idConverter);
    }

    @Test
    void isOwner_WhenUserMatchesEmail_ShouldReturnTrue() {
        UUID id = UUID.randomUUID();
        TestUser user = new TestUser();
        user.setEmail("owner@example.com");

        when(idConverter.fromString("user-id")).thenReturn(id);
        when(userService.getUserById(id)).thenReturn(user);

        assertThat(userSecurityService.isOwner("owner@example.com", "user-id")).isTrue();
    }

    @Test
    void isOwner_WhenUserNotFound_ShouldReturnFalse() {
        UUID id = UUID.randomUUID();
        when(idConverter.fromString("missing-id")).thenReturn(id);
        when(userService.getUserById(id)).thenThrow(new ResourceNotFoundException("Not found"));

        assertThat(userSecurityService.isOwner("owner@example.com", "missing-id")).isFalse();
    }

    @Test
    void isOwnerUsername_WhenUsernameMatchesEmail_ShouldReturnTrue() {
        TestUser user = new TestUser();
        user.setEmail("owner@example.com");

        when(userService.getUserByUserName("ownerUser")).thenReturn(user);

        assertThat(userSecurityService.isOwnerUsername("owner@example.com", "ownerUser")).isTrue();
    }

    @Test
    void isOwnerUsername_WhenUsernameNotFound_ShouldReturnFalse() {
        when(userService.getUserByUserName("missingUser")).thenThrow(new ResourceNotFoundException("Not found"));

        assertThat(userSecurityService.isOwnerUsername("owner@example.com", "missingUser")).isFalse();
    }

    private static class TestUser implements AuthUser<UUID, TestRole> {
        private UUID id;
        private String username;
        private String email;
        private String password;
        private Long version;
        private Set<TestRole> roles = Set.of();
        private Instant createdAt;
        private Instant updatedAt;

        @Override
        public UUID getId() {
            return id;
        }

        @Override
        public String getUsername() {
            return username;
        }

        @Override
        public String getEmail() {
            return email;
        }

        @Override
        public String getPassword() {
            return password;
        }

        @Override
        public Set<TestRole> getRoles() {
            return roles;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return Set.of();
        }

        @Override
        public Long getVersion() {
            return version;
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
        public void setId(UUID id) {
            this.id = id;
        }

        @Override
        public void setUsername(String username) {
            this.username = username;
        }

        @Override
        public void setEmail(String email) {
            this.email = email;
        }

        @Override
        public void setPassword(String password) {
            this.password = password;
        }

        @Override
        public void setRoles(Set<TestRole> roles) {
            this.roles = roles;
        }

        @Override
        public void addRole(TestRole role) {
        }

        @Override
        public void removeRole(TestRole role) {
        }

        @Override
        public void setVersion(Long version) {
            this.version = version;
        }

        @Override
        public void setCreatedAt(Instant createdAt) {
            this.createdAt = createdAt;
        }

        @Override
        public void setUpdatedAt(Instant updatedAt) {
            this.updatedAt = updatedAt;
        }
    }

    private static class TestRole implements Role {
        @Override
        public String getAuthority() {
            return "ROLE_USER";
        }
    }
}
