package com.ricardo.auth.controller;

import com.ricardo.auth.core.Role;
import com.ricardo.auth.core.RoleService;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.domain.user.Username;
import com.ricardo.auth.dto.AddRoleRequest;
import com.ricardo.auth.dto.BulkRoleUpdateRequest;
import com.ricardo.auth.dto.RemoveRoleRequest;
import com.ricardo.auth.dto.UserRolesResponse;
import com.ricardo.auth.helper.IdConverter;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Role management controller with proper authorization.
 * All endpoints require ADMIN role or specific permissions.
 * Uses usernames for security (prevents ID enumeration attacks).
 */
@RestController
@RequestMapping("/api/users")
@Validated
@Slf4j
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Role Management", description = "User role management operations")
public class RoleManagementController<U extends AuthUser<ID, R>, R extends Role, ID> {

    private final RoleService<U, R, ID> roleService;
    private final UserService<U, R, ID> userService;
    private final IdConverter<ID> idConverter;

    public RoleManagementController(RoleService<U, R, ID> roleService, UserService<U, R, ID> userService, IdConverter<ID> idConverter) {
        this.roleService = roleService;
        this.userService = userService;
        this.idConverter = idConverter;
    }

    /**
     * Validates username using the Username VO which is the information expert.
     * Returns the normalized username string for service calls.
     */
    private String validateUsername(String usernameStr) {
        try {
            // Let Username VO handle all validation logic
            Username username = Username.valueOf(usernameStr);
            return username.getUsername();
        } catch (IllegalArgumentException e) {
            log.warn("Username validation failed for '{}': {}", usernameStr, e.getMessage());
            throw e; // Re-throw with original message from Username VO
        }
    }

    /**
     * Gets user by username and converts to ID for service layer operations.
     */
    private ID getUserIdByUsername(String username) {
        try {
            U user = userService.getUserByUserName(username);
            if (user == null) {
                throw new ResourceNotFoundException("User not found: " + username);
            }
            return user.getId();
        } catch (ResourceNotFoundException e) {
            throw e;
        } catch (Exception e) {
            log.warn("User lookup failed for username: {}", username, e);
            throw new IllegalArgumentException("User lookup failed: " + username, e);
        }
    }

    /**
     * Get all roles for a specific user.
     * Requires ADMIN role or USER_READ permission.
     */
    @GetMapping("/{username}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
            summary = "Get user roles",
            description = "Retrieve all roles assigned to a specific user by username"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "User roles retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UserRolesResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid username format",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "User not found",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access denied - Admin role required",
                    content = @Content(mediaType = "application/json")
            )
    })
    @SecurityRequirement(name = "CookieAuth")
    public ResponseEntity<UserRolesResponse> getUserRoles(
            @Parameter(description = "Username", required = true)
            @PathVariable String username) {
        try {
            String validatedUsername = validateUsername(username);
            ID userId = getUserIdByUsername(validatedUsername);

            UserRolesResponse response = roleService.getUserRoles(userId);

            log.debug("Retrieved roles for user: {}", validatedUsername);
            return ResponseEntity.ok(response);

        } catch (ResourceNotFoundException e) {
            log.warn("User not found for username: {}: {}", username, e.getMessage());
            return ResponseEntity.status(404).build();
        } catch (IllegalArgumentException e) {
            log.warn("Invalid request for user roles: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        } catch (SecurityException e) {
            log.warn("Security violation accessing user roles for username: {}", username);
            return ResponseEntity.status(403).build();

        } catch (Exception e) {
            log.error("Error retrieving user roles for username: {}", username);
            return ResponseEntity.status(500).build();
        }
    }

    /**
     * Add a role to a user.
     * Requires ADMIN role.
     */
    @PostMapping("/{username}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
            summary = "Add role to user",
            description = "Assign a role to a specific user by username"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Role added successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = Map.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid request data or username format",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "User or role not found",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access denied - Admin role required",
                    content = @Content(mediaType = "application/json")
            )
    })
    @SecurityRequirement(name = "CookieAuth")
    public ResponseEntity<Map<String, String>> addRoleToUser(
            @Parameter(description = "Username", required = true)
            @PathVariable String username,
            @Parameter(description = "Role assignment request", required = true)
            @Valid @RequestBody AddRoleRequest request) {

        try {
            String validatedUsername = validateUsername(username);
            ID userId = getUserIdByUsername(validatedUsername);

            roleService.addRoleToUser(userId, request.getRoleName(), request.getReason());

            log.info("Role '{}' added to user {} with reason: {}",
                    request.getRoleName(), validatedUsername, request.getReason());

            return ResponseEntity.ok(Map.of(
                    "message", "Role added successfully.",
                    "username", validatedUsername,
                    "role", request.getRoleName()
            ));

        } catch (ResourceNotFoundException e) {
            log.warn("User or role not found for username: {}: {}", username, e.getMessage());
            return ResponseEntity.status(404)
                    .body(Map.of("error", e.getMessage()));
        } catch (IllegalArgumentException e) {
            log.warn("Invalid role addition request for username {}: {}", username, e.getMessage());
            return ResponseEntity.badRequest()
                    .body(Map.of("error", e.getMessage()));

        } catch (SecurityException e) {
            log.warn("Security violation adding role to username: {}", username);
            return ResponseEntity.status(403)
                    .body(Map.of("error", "Insufficient permissions."));

        } catch (Exception e) {
            log.error("Error adding role to user: {}", username);
            return ResponseEntity.status(500)
                    .body(Map.of("error", "An error occurred while adding the role."));
        }
    }

    /**
     * Remove a role from a user.
     * Requires ADMIN role or USER_WRITE permission.
     */
    @DeleteMapping("/{username}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
            summary = "Remove role from user",
            description = "Remove a role assignment from a specific user by username"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Role removed successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = Map.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid request data or username format",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "User or role not found",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access denied - Admin role required",
                    content = @Content(mediaType = "application/json")
            )
    })
    @SecurityRequirement(name = "CookieAuth")
    public ResponseEntity<Map<String, String>> removeRoleFromUser(
            @Parameter(description = "Username", required = true)
            @PathVariable String username,
            @Parameter(description = "Role removal request", required = true)
            @Valid @RequestBody RemoveRoleRequest request) {

        try {
            String validatedUsername = validateUsername(username);
            ID userId = getUserIdByUsername(validatedUsername);

            roleService.removeRoleFromUser(userId, request.getRoleName(), request.getReason());

            log.info("Role '{}' removed from user {} with reason: {}",
                    request.getRoleName(), validatedUsername, request.getReason());

            return ResponseEntity.ok(Map.of(
                    "message", "Role removed successfully.",
                    "username", validatedUsername,
                    "role", request.getRoleName()
            ));

        } catch (IllegalArgumentException e) {
            log.warn("Invalid role removal request for username {}: {}", username, e.getMessage());
            return ResponseEntity.badRequest()
                    .body(Map.of("error", e.getMessage()));

        } catch (SecurityException e) {
            log.warn("Security violation removing role from username: {}", username);
            return ResponseEntity.status(403)
                    .body(Map.of("error", "Insufficient permissions."));

        } catch (Exception e) {
            log.error("Error removing role from user: {}", username);
            return ResponseEntity.status(500)
                    .body(Map.of("error", "An error occurred while removing the role."));
        }
    }

    /**
     * Bulk role operations for a user.
     * Requires ADMIN role.
     */
    @PutMapping("/{username}/roles/bulk")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
            summary = "Bulk update user roles",
            description = "Update multiple role assignments for a user in a single operation by username"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Roles updated successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = Map.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid request data or username format",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "User not found",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access denied - Admin role required",
                    content = @Content(mediaType = "application/json")
            )
    })
    @SecurityRequirement(name = "CookieAuth")
    public ResponseEntity<Map<String, String>> bulkUpdateUserRoles(
            @Parameter(description = "Username", required = true)
            @PathVariable String username,
            @Parameter(description = "Bulk role update request", required = true)
            @Valid @RequestBody BulkRoleUpdateRequest request) {

        try {
            String validatedUsername = validateUsername(username);
            ID userId = getUserIdByUsername(validatedUsername);

            roleService.bulkUpdateUserRoles(userId, request.getRolesToAdd(),
                    request.getRolesToRemove(), request.getReason());

            log.info("Bulk role update completed for user {} - Added: {}, Removed: {}",
                    validatedUsername, request.getRolesToAdd(), request.getRolesToRemove());

            return ResponseEntity.ok(Map.of(
                    "message", "Roles updated successfully.",
                    "username", validatedUsername,
                    "addedRoles", String.join(", ", request.getRolesToAdd()),
                    "removedRoles", String.join(", ", request.getRolesToRemove())
            ));

        } catch (IllegalArgumentException e) {
            log.warn("Invalid bulk role update request for username {}: {}", username, e.getMessage());
            return ResponseEntity.badRequest()
                    .body(Map.of("error", e.getMessage()));

        } catch (SecurityException e) {
            log.warn("Security violation in bulk role update for username: {}", username);
            return ResponseEntity.status(403)
                    .body(Map.of("error", "Insufficient permissions."));

        } catch (Exception e) {
            log.error("Error in bulk role update for user: {}", username);
            return ResponseEntity.status(500)
                    .body(Map.of("error", "An error occurred while updating roles."));
        }
    }
}
