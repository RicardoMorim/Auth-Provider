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
import com.ricardo.auth.helper.CacheHelper;
import com.ricardo.auth.helper.IdConverter;
import com.ricardo.auth.helper.RoleMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
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
 * @param <U>  the type parameter
 * @param <R>  the type parameter
 * @param <ID> the type parameter
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
    private final CacheHelper<U, R, ID> cacheHelper;

    /**
     * Instantiates a new Role service.
     *
     * @param userService    the user service
     * @param roleMapper     the role mapper
     * @param authProperties the auth properties
     * @param eventPublisher the event publisher
     * @param idConverter    the id converter
     * @param cacheHelper    the cache helper
     */
    public RoleServiceImpl(UserService<U, R, ID> userService,
                           RoleMapper<R> roleMapper,
                           AuthProperties authProperties,
                           Publisher eventPublisher, IdConverter<ID> idConverter, CacheHelper<U, R, ID> cacheHelper) {
        this.userService = userService;
        this.roleMapper = roleMapper;
        this.authProperties = authProperties;
        this.eventPublisher = eventPublisher;
        this.idConverter = idConverter;
        this.cacheHelper = cacheHelper;
    }

    private static String sanitizeForLogging(String input) {
        if (input == null) {
            return "null";
        }
        return input
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
                .replace("\"", "\\\"")
                .trim();
    }

    private static String sanitizeIdForLogging(Object id) {
        if (id == null) return "null";
        return sanitizeForLogging(id.toString());
    }

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public void addRoleToUser(ID userId, String roleName, String reason) {
        validateRoleOperation(userId, roleName);

        log.info("Adding role {} to user {} by admin {} with reason: {}",
                sanitizeForLogging(roleName),
                sanitizeIdForLogging(userId),
                sanitizeForLogging(getCurrentUsername()),
                sanitizeForLogging(reason));

        U user = userService.getUserById(userId);

        try {
            R role = roleMapper.mapRole(roleName.trim().toUpperCase());

            if (role == null) {
                log.warn("Invalid role name: {}", sanitizeForLogging(roleName));
                throw new IllegalArgumentException("Invalid role: " + sanitizeForLogging(roleName));
            }

            if (user.getRoles().contains(role)) {
                log.warn("User {} already has role {}", sanitizeIdForLogging(userId), sanitizeForLogging(roleName));
                return;
            }

            user.addRole(role);
            userService.updateUser(userId, user);

            log.info("Role {} added to user {} by admin {} with reason: {}",
                    sanitizeForLogging(roleName),
                    sanitizeIdForLogging(userId),
                    sanitizeForLogging(getCurrentUsername()),
                    sanitizeForLogging(reason));

            this.cacheHelper.evictUserCache(user);

            if (authProperties.getRoleManagement().isEnableRoleEvents()) {
                eventPublisher.publishEvent(new UserRoleAddedEvent(
                        user.getUsername(),
                        user.getEmail(),
                        role
                ));
            }

        } catch (RoleMapper.RoleMappingException e) {
            log.error("Invalid role name: {}", sanitizeForLogging(roleName));
            throw new IllegalArgumentException("Invalid role: " + sanitizeForLogging(roleName), e);
        }
    }

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public void removeRoleFromUser(ID userId, String roleName, String reason) {
        validateRoleOperation(userId, roleName);

        U user = userService.getUserById(userId);

        try {
            R role = roleMapper.mapRole(roleName.trim().toUpperCase());

            if (!user.getRoles().contains(role)) {
                log.warn("User {} does not have role {}", sanitizeIdForLogging(userId), sanitizeForLogging(roleName));
                return;
            }

            R adminRole = roleMapper.mapRole("ADMIN");
            if (role.equals(adminRole) && isLastAdminRole(user, role)) {
                throw new SecurityException("Cannot remove the last admin role");
            }

            user.removeRole(role);
            userService.updateUser(userId, user);

            log.info("Role {} removed from user {} by admin {} with reason: {}",
                    sanitizeForLogging(roleName),
                    sanitizeIdForLogging(userId),
                    sanitizeForLogging(getCurrentUsername()),
                    sanitizeForLogging(reason));

            this.cacheHelper.evictUserCache(user);

            if (authProperties.getRoleManagement().isEnableRoleEvents()) {
                eventPublisher.publishEvent(new UserRoleRemovedEvent(
                        user.getUsername(),
                        user.getEmail(),
                        role
                ));
            }

        } catch (RoleMapper.RoleMappingException e) {
            log.error("Invalid role name: {}", sanitizeForLogging(roleName));
            throw new IllegalArgumentException("Invalid role: " + sanitizeForLogging(roleName), e);
        }
    }

    @Override
    @Cacheable(value = "userHasRoleCache", key = "#userId + '::' + #roleName")
    public boolean userHasRole(ID userId, String roleName) {
        try {
            U user = userService.getUserById(userId);
            R role = roleMapper.mapRole(roleName.trim().toUpperCase());
            return user.getRoles().contains(role);
        } catch (RoleMapper.RoleMappingException e) {
            log.error("Invalid role name: {}", sanitizeForLogging(roleName));
            throw new IllegalArgumentException("Invalid role: " + sanitizeForLogging(roleName), e);
        } catch (RuntimeException e) {
            log.error("Error checking role {} for user {}: {}",
                    sanitizeForLogging(roleName),
                    sanitizeIdForLogging(userId),
                    sanitizeForLogging(e.getMessage()));
            throw e;
        }
    }

    @Override
    @Cacheable(value = "getUserRolesCache", key = "#userId", condition = "#userId != null")
    public Set<R> getSetUserRoles(ID userId) {
        U user = userService.getUserById(userId);

        return user.getRoles();
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    @Cacheable(value = "getUserRolesCache", key = "#userId", condition = "#userId != null")
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
                sanitizeIdForLogging(userId),
                sanitizeForLogging(getCurrentUsername()),
                sanitizeForLogging(reason));

        if (rolesToAdd != null) {
            for (String roleName : rolesToAdd) {
                addRoleToUser(userId, roleName, reason);
            }
        }

        if (rolesToRemove != null) {
            for (String roleName : rolesToRemove) {
                removeRoleFromUser(userId, roleName, reason);
            }
        }

        cacheHelper.evictUserCache(userService.getUserById(userId));

        log.info("Bulk role update completed for user {}", sanitizeIdForLogging(userId));
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
