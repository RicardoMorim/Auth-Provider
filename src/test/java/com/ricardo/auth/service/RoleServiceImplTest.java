package com.ricardo.auth.service;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.Publisher;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.user.*;
import com.ricardo.auth.dto.UserRolesResponse;
import com.ricardo.auth.helper.IdConverter;
import com.ricardo.auth.helper.RoleMapper;
import com.ricardo.auth.repository.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The type Role service impl test.
 */
@SpringBootTest
@ActiveProfiles("test")
class RoleServiceImplTest {

    @Autowired
    private UserService<User, AppRole, UUID> userService;

    @Autowired
    private RoleMapper<AppRole> roleMapper;

    @Autowired
    private Publisher eventPublisher;

    @Autowired
    private IdConverter<UUID> idConverter;

    @Autowired
    private AuthProperties authProperties;

    @Autowired
    private RoleServiceImpl<User, AppRole, UUID> roleService;

    @Autowired
    private UserRepository<User, AppRole, UUID> userRepository;

    /**
     * Sets up.
     */
    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    /**
     * Add role to user with valid parameters should add role.
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void addRoleToUser_WithValidParameters_ShouldAddRole() {
        // Given
        User user = createUser(1);
        String roleName = "ADMIN";
        String reason = "User promotion";

        user = userRepository.saveUser(user);

        // When
        roleService.addRoleToUser(user.getId(), roleName, reason);

        // Then
        User updatedUser = userService.getUserById(user.getId());
        assertThat(updatedUser.getRoles()).contains(AppRole.ADMIN);

    }

    /**
     * Add role to user with null user id should throw exception.
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void addRoleToUser_WithNullUserId_ShouldThrowException() {
        // When & Then
        assertThatThrownBy(() -> roleService.addRoleToUser(null, "MODERATOR", "reason"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("User ID cannot be null");
    }

    /**
     * Add role to user with null role name should throw exception.
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void addRoleToUser_WithNullRoleName_ShouldThrowException() {
        // Given
        User user = createUser(1);
        user = userRepository.saveUser(user);

        // When & Then
        User finalUser = user;
        assertThatThrownBy(() -> roleService.addRoleToUser(finalUser.getId(), null, "reason"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Role name cannot be null or empty");
    }

    /**
     * Add role to user with empty role name should throw exception.
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void addRoleToUser_WithEmptyRoleName_ShouldThrowException() {
        // Given
        User user = createUser(1);

        user = userRepository.saveUser(user);
        // When & Then
        User finalUser = user;
        assertThatThrownBy(() -> roleService.addRoleToUser(finalUser.getId(), "", "reason"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Role name cannot be null or empty");
    }

    /**
     * Add role to user when user already has role should log and return.
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void addRoleToUser_WhenUserAlreadyHasRole_ShouldLogAndReturn() {
        // Given
        User user = createUser(1);
        user.addRole(AppRole.VIP);
        userRepository.saveUser(user);

        String roleName = "VIP";

        // When
        roleService.addRoleToUser(user.getId(), roleName, "reason");

        // Then
        User updatedUser = userService.getUserById(user.getId());
        long moderatorRoleCount = updatedUser.getRoles().stream()
                .filter(role -> role.equals(AppRole.VIP))
                .count();
        assertThat(moderatorRoleCount).isEqualTo(1); // Should still have only one
    }

    /**
     * Remove role from user with valid parameters should remove role.
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void removeRoleFromUser_WithValidParameters_ShouldRemoveRole() {
        // Given
        User user = createUser(1);
        AppRole moderatorRole = AppRole.ADMIN;
        user.addRole(moderatorRole);
        userRepository.saveUser(user);

        String roleName = "ADMIN";
        String reason = "User demotion";

        // When
        roleService.removeRoleFromUser(user.getId(), roleName, reason);

        // Then
        User updatedUser = userService.getUserById(user.getId());
        assertThat(updatedUser.getRoles()).doesNotContain(moderatorRole);
    }

    /**
     * Remove role from user when user does not have role should log and return.
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void removeRoleFromUser_WhenUserDoesNotHaveRole_ShouldLogAndReturn() {
        // Given
        User user = createUser(1);
        User user2 = createUser(2);
        user2.addRole(AppRole.ADMIN);
        user.addRole(AppRole.ADMIN);

        userRepository.saveUser(user);
        userRepository.saveUser(user2);

        // When
        roleService.removeRoleFromUser(user.getId(), "ADMIN", "reason");

        // Then
        User updatedUser = userService.getUserById(user.getId());
        assertThat(updatedUser.getRoles()).doesNotContain(AppRole.ADMIN);
    }

    /**
     * Gets user roles with valid user id should return user roles response.
     */
    @Test
    @WithMockUser(roles = {"ADMIN", "USER_READ"})
    void getUserRoles_WithValidUserId_ShouldReturnUserRolesResponse() {
        // Given
        User user = createUser(1);
        AppRole userRole = AppRole.USER;
        AppRole moderatorRole = AppRole.ADMIN;
        user.addRole(userRole);
        user.addRole(moderatorRole);
        userRepository.saveUser(user);

        // When
        UserRolesResponse response = roleService.getUserRoles(user.getId());

        // Then
        assertThat(response.getUserId()).isEqualTo(user.getId().toString());
        assertThat(response.getUsername()).isEqualTo(user.getUsername());
        assertThat(response.getEmail()).isEqualTo(user.getEmail());
        assertThat(response.getRoles()).containsExactlyInAnyOrder("USER", "ADMIN");
    }

    /**
     * Gets user roles with null user id should throw exception.
     */
    @Test
    @WithMockUser(roles = {"ADMIN"})
    void getUserRoles_WithNullUserId_ShouldThrowException() {
        // When & Then
        assertThatThrownBy(() -> roleService.getUserRoles(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("User ID cannot be null");
    }

    /**
     * Bulk update user roles with valid parameters should update roles.
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void bulkUpdateUserRoles_WithValidParameters_ShouldUpdateRoles() {
        // Given
        User user = createUser(1);
        AppRole userRole = AppRole.USER;
        user.addRole(userRole);
        userRepository.saveUser(user);

        List<String> rolesToAdd = List.of("ADMIN", "VIP");
        List<String> rolesToRemove = List.of("USER");
        String reason = "Bulk update";

        // When
        roleService.bulkUpdateUserRoles(user.getId(), rolesToAdd, rolesToRemove, reason);

        // Then
        User updatedUser = userService.getUserById(user.getId());
        assertThat(updatedUser.getRoles()).contains(
                AppRole.ADMIN,
                AppRole.VIP
        );
        assertThat(updatedUser.getRoles()).doesNotContain(userRole);

    }

    /**
     * Bulk update user roles with null user id should throw exception.
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void bulkUpdateUserRoles_WithNullUserId_ShouldThrowException() {
        // Given
        List<String> rolesToAdd = List.of("ADMIN");
        List<String> rolesToRemove = List.of("USER");

        // When & Then
        assertThatThrownBy(() -> roleService.bulkUpdateUserRoles(null, rolesToAdd, rolesToRemove, "reason"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("User ID cannot be null");
    }

    /**
     * Bulk update user roles with no operations should throw exception.
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void bulkUpdateUserRoles_WithNoOperations_ShouldThrowException() {
        // Given
        User user = createUser(1);

        user = userRepository.saveUser(user);

        // When & Then
        User finalUser = user;
        assertThatThrownBy(() -> roleService.bulkUpdateUserRoles(finalUser.getId(), null, null, "reason"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("At least one role operation must be specified");
    }

    /**
     * User has role with existing role should return true.
     */
    @Test
    void userHasRole_WithExistingRole_ShouldReturnTrue() {
        // Given
        User user = createUser(1);
        AppRole userRole = AppRole.USER;
        user.addRole(userRole);
        userRepository.saveUser(user);

        String roleName = "USER";

        // When
        boolean hasRole = roleService.userHasRole(user.getId(), roleName);

        // Then
        assertThat(hasRole).isTrue();
    }

    /**
     * User has role with non existing role should return false.
     */
    @Test
    void userHasRole_WithNonExistingRole_ShouldReturnFalse() {
        // Given
        User user = createUser(1);
        user = userRepository.saveUser(user);

        String roleName = "ADMIN";

        // When
        boolean hasRole = roleService.userHasRole(user.getId(), roleName);

        // Then
        assertThat(hasRole).isFalse();
    }

    /**
     * Add role to user without admin role should throw access denied exception.
     */
    @Test
    void addRoleToUser_WithoutAdminRole_ShouldThrowAccessDeniedException() {
        // Given
        User user = createUser(1);
        user = userRepository.saveUser(user);

        // When & Then
        User finalUser = user;
        assertThatThrownBy(() -> roleService.addRoleToUser(finalUser.getId(), "ADMIN", "reason"))
                .isInstanceOf(AuthenticationCredentialsNotFoundException.class);
    }


    private User createUser(int i) {
        return new User(Username.valueOf("user" + i), Email.valueOf("user" + i + "@email.com"), Password.fromHash("hashedPassword"));
    }
}