package com.ricardo.auth.service;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.Publisher;
import com.ricardo.auth.core.Role;
import com.ricardo.auth.core.RoleService;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.domainevents.UserRoleAddedEvent;
import com.ricardo.auth.domain.domainevents.UserRoleRemovedEvent;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.dto.UserRolesResponse;
import com.ricardo.auth.helper.IdConverter;
import com.ricardo.auth.helper.RoleMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Implementation of RoleService that provides secure role management.
 * Follows OWASP security guidelines and your decoupled architecture.
 *
 * @since 3.1.0
 */
@Service
@Slf4j
public class RoleServiceImpl<U extends AuthUser<ID, R>, R extends Role, ID> implements RoleService<U, R, ID> {

    private final UserService<U, R, ID> userService;
    private final RoleMapper<R> roleMapper;
    private final AuthProperties authProperties;
    private final Publisher eventPublisher;
    private final IdConverter<ID> idConverter;

    public RoleServiceImpl(UserService<U, R, ID> userService,
                           RoleMapper<R> roleMapper,
                           AuthProperties authProperties,
                           Publisher eventPublisher, IdConverter<ID> idConverter) {
        this.userService = userService;
        this.roleMapper = roleMapper;
        this.authProperties = authProperties;
        this.eventPublisher = eventPublisher;
        this.idConverter = idConverter;
    }

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public void addRoleToUser(ID userId, String roleName, String reason) {
        validateRoleOperation(userId, roleName);

        log.info("Adding role {} to user {} by admin {} with reason: {}",
                roleName, userId, getCurrentUsername(), reason);

        // Get user first to validate existence
        U user = userService.getUserById(userId);

        try {
            // Convert string to role type
            R role = roleMapper.mapRole(roleName.trim().toUpperCase());

            // Check if user already has this role
            if (user.getRoles().contains(role)) {
                log.warn("User {} already has role {}", userId, roleName);
                return;
            }

            // Add role to user
            user.addRole(role);
            userService.updateUser(userId, user);

            log.info("Role {} added to user {} by admin {} with reason: {}",
                    roleName, userId, getCurrentUsername(), reason);

            // Publish event if enabled
            if (authProperties.getRoleManagement().isEnableRoleEvents()) {
                eventPublisher.publishEvent(new UserRoleAddedEvent(
                        user.getUsername(),
                        user.getEmail(),
                        role
                ));
            }

        } catch (RoleMapper.RoleMappingException e) {
            log.error("Invalid role name: {}", roleName);
            throw new IllegalArgumentException("Invalid role: " + roleName, e);
        }
    }

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public void removeRoleFromUser(ID userId, String roleName, String reason) {
        validateRoleOperation(userId, roleName);

        // Get user first to validate existence
        U user = userService.getUserById(userId);

        try {
            // Convert string to role type
            R role = roleMapper.mapRole(roleName.trim().toUpperCase());

            // Check if user has this role
            if (!user.getRoles().contains(role)) {
                log.warn("User {} does not have role {}", userId, roleName);
                return;
            }

            // Prevent removing the last admin role
            R adminRole = roleMapper.mapRole("ADMIN");
            if (role.equals(adminRole) && isLastAdminRole(user, role)) {
                throw new SecurityException("Cannot remove the last admin role");
            }

            // Remove role from user
            user.removeRole(role);
            userService.updateUser(userId, user);

            log.info("Role {} removed from user {} by admin {} with reason: {}",
                    roleName, userId, getCurrentUsername(), reason);

            // Publish event if enabled
            if (authProperties.getRoleManagement().isEnableRoleEvents()) {
                eventPublisher.publishEvent(new UserRoleRemovedEvent(
                        user.getUsername(),
                        user.getEmail(),
                        role
                ));
            }

        } catch (RoleMapper.RoleMappingException e) {
            log.error("Invalid role name: {}", roleName);
            throw new IllegalArgumentException("Invalid role: " + roleName, e);
        }
    }

    @Override
    public boolean userHasRole(ID userId, String roleName) {
        try {
            U user = userService.getUserById(userId);
            R role = roleMapper.mapRole(roleName.trim().toUpperCase());
            return user.getRoles().contains(role);
        } catch (RoleMapper.RoleMappingException e) {
            log.error("Invalid role name: {}", roleName);
            throw new IllegalArgumentException("Invalid role: " + roleName, e);
        } catch (RuntimeException e) {
            log.error("Error checking role {} for user {}: {}", roleName, userId, e.getMessage());
            throw e;
        }
    }

    @Override
    public Set<R> getSetUserRoles(ID userId) {
        U user = userService.getUserById(userId);
        return user.getRoles();
    }

    @Override
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('USER_READ')")
    public UserRolesResponse getUserRoles(ID userId) {
        if (userId == null) {
            throw new IllegalArgumentException("User ID cannot be null");
        }

        try {
            U user = userService.getUserById(userId);

            // Convert roles to string list
            List<String> roleNames = new ArrayList<>();

            user.getRoles().forEach(role -> roleNames.add(role.toString()));


            return new UserRolesResponse(
                    idConverter.toString(userId),
                    user.getUsername(),
                    user.getEmail(),
                    roleNames
            );

        } catch (Exception e) {
            throw e;
        }
    }

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public void bulkUpdateUserRoles(ID userId, List<String> rolesToAdd,
                                    List<String> rolesToRemove, String reason) {
        if (userId == null) {
            throw new IllegalArgumentException("User ID cannot be null");
        }

        if ((rolesToAdd == null || rolesToAdd.isEmpty()) &&
                (rolesToRemove == null || rolesToRemove.isEmpty())) {
            throw new IllegalArgumentException("At least one role operation must be specified");
        }

        log.info("Bulk role update for user {} by admin {} with reason: {}",
                userId, getCurrentUsername(), reason);


        // Add roles
        if (rolesToAdd != null && !rolesToAdd.isEmpty()) {
            for (String roleName : rolesToAdd) {
                addRoleToUser(userId, roleName, reason);
            }
        }

        // Remove roles
        if (rolesToRemove != null && !rolesToRemove.isEmpty()) {
            for (String roleName : rolesToRemove) {
                removeRoleFromUser(userId, roleName, reason);
            }
        }

        log.info("Bulk role update completed for user {}", userId);
    }

    private void validateRoleOperation(ID userId, String roleName) {
        if (userId == null) {
            throw new IllegalArgumentException("User ID cannot be null");
        }

        if (roleName == null || roleName.trim().isEmpty()) {
            throw new IllegalArgumentException("Role name cannot be null or empty");
        }

        // Additional validation: prevent self-modification if not allowed
        if (!authProperties.getRoleManagement().isAllowSelfRoleModification()) {
            String currentUserId = getCurrentUserId();
            if (currentUserId != null && currentUserId.equals(idConverter.toString(userId))) {
                throw new SecurityException("Self role modification is not allowed");
            }
        }
    }

    private boolean isLastAdminRole(U user, R roleToRemove) {
        try {
            R adminRole = roleMapper.mapRole("ADMIN");
            return roleToRemove.equals(adminRole) &&
                    user.getRoles().contains(adminRole) &&
                    userService.countAdmins() <= 1;
        } catch (Exception e) {
            log.warn("Could not check for admin role: {}", e.getMessage());
            return false;
        }
    }

    private String getCurrentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null ? auth.getName() : "system";
    }

    private String getCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof AuthUser<?, ?> user) {
            return user.getId().toString();
        }
        return null;
    }
}
