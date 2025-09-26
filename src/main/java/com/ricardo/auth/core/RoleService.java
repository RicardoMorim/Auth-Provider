package com.ricardo.auth.core;

import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.dto.UserRolesResponse;

import java.util.List;
import java.util.Set;

/**
 * Service interface for managing user roles.
 * Provides secure role management operations with proper authorization.
 *
 * @param <U>  the type parameter
 * @param <R>  the type parameter
 * @param <ID> the type parameter
 */
public interface RoleService<U extends AuthUser<ID, R>, R extends Role, ID> {

    /**
     * Adds a role to a user. Requires admin privileges.
     *
     * @param userId   the user ID
     * @param roleName the role name to add
     * @param reason   the reason for adding the role
     * @throws SecurityException        if the current user lacks permission
     * @throws IllegalArgumentException if userId or roleName is invalid
     */
    void addRoleToUser(ID userId, String roleName, String reason);

    /**
     * Removes a role from a user. Requires admin privileges.
     *
     * @param userId   the user ID
     * @param roleName the role name to remove
     * @param reason   the reason for removing the role
     * @throws SecurityException        if the current user lacks permission
     * @throws IllegalArgumentException if userId or roleName is invalid
     */
    void removeRoleFromUser(ID userId, String roleName, String reason);

    /**
     * Checks if a user has a specific role.
     *
     * @param userId   the user ID
     * @param roleName the role name to check
     * @return true if the user has the role, false otherwise
     */
    boolean userHasRole(ID userId, String roleName);

    /**
     * Gets all roles for a user as domain objects.
     *
     * @param userId the user ID
     * @return set of roles for the user
     */
    Set<R> getSetUserRoles(ID userId);

    /**
     * Gets all roles and permissions for a user as DTO.
     *
     * @param userId the user ID (must be UUID)
     * @return UserRolesResponse containing roles and permissions
     * @throws IllegalArgumentException if userId is null
     * @throws SecurityException        if access is denied
     */
    UserRolesResponse getUserRoles(ID userId);

    /**
     * Bulk update user roles (add and remove in one operation).
     *
     * @param userId        the user ID (must be UUID)
     * @param rolesToAdd    list of roles to add
     * @param rolesToRemove list of roles to remove
     * @param reason        the reason for the bulk operation
     * @throws IllegalArgumentException if parameters are invalid
     * @throws SecurityException        if operation is not allowed
     */
    void bulkUpdateUserRoles(ID userId, List<String> rolesToAdd,
                             List<String> rolesToRemove, String reason);
}