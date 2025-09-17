package com.ricardo.auth.controller;

import com.ricardo.auth.core.Role;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.DatabaseOperation;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.dto.CreateUserRequestDTO;
import com.ricardo.auth.dto.UpdateUserRequestDTO;
import com.ricardo.auth.dto.UserDTO;
import com.ricardo.auth.dto.UserDTOMapper;
import com.ricardo.auth.factory.AuthUserFactory;
import com.ricardo.auth.helper.IdConverter;
import com.ricardo.auth.service.UserMetricsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@Validated
@Tag(name = "User Management", description = "User CRUD operations")
public class UserController<U extends AuthUser<ID, R>, R extends Role, ID> implements UserApiEndpoint {
    private final UserService<U, R, ID> userService;
    private final AuthUserFactory<U, R, ID> userBuilder;
    private final IdConverter<ID> idConverter;

    private final UserMetricsService metricsCollector;

    public UserController(UserService<U, R, ID> userService, AuthUserFactory<U, R, ID> userBuilder, IdConverter<ID> idConverter, UserMetricsService metricsCollector) {
        this.userService = userService;
        this.userBuilder = userBuilder;
        this.idConverter = idConverter;
        this.metricsCollector = metricsCollector;
    }

    @PostMapping("/create")
    public ResponseEntity<UserDTO> createUser(
            @Parameter(description = "User creation request", required = true)
            @Valid @RequestBody CreateUserRequestDTO request) {
        U user = userBuilder.create(request);
        U newUser = userService.createUser(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(UserDTOMapper.toDTO(newUser));
    }

    @GetMapping("/email/{email}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserDTO> getUserByEmail(
            @Parameter(description = "User email address", required = true)
            @PathVariable String email) {
        U user = userService.getUserByEmail(email);
        return ResponseEntity.ok(UserDTOMapper.toDTO(user));
    }

    @GetMapping("/{username}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurityService.isOwnerUsername(authentication.name, #username)")
    public ResponseEntity<UserDTO> getUserById(@PathVariable String username) {
        U user = userService.getUserByUserName(username);
        return ResponseEntity.ok(UserDTOMapper.toDTO(user));
    }

    @GetMapping("/exists/{email}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Boolean> userExists(@PathVariable String email) {
        boolean exists = userService.userExists(email);
        return ResponseEntity.ok(exists);
    }

    @PutMapping("/update/{username}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurityService.isOwnerUsername(authentication.name, #username)")
    public ResponseEntity<UserDTO> updateUser(@Valid @RequestBody UpdateUserRequestDTO request, @PathVariable("username") String username, Authentication authentication) {
        U existingUser = userService.getUserByUserName(username);
        if (existingUser == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        ID id = existingUser.getId();
        U updatedUser = userService.updateEmailAndUsername(id, request.getEmail(), request.getUsername());
        return ResponseEntity.ok(UserDTOMapper.toDTO(updatedUser));
    }

    @DeleteMapping("/delete/{username}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurityService.isOwnerUsername(authentication.name, #username)")
    public ResponseEntity<Void> deleteUser(@PathVariable String username, Authentication authentication) {
        U user = userService.getUserByUserName(username);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        userService.deleteUser(user.getId());
        return ResponseEntity.noContent().build();
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
            summary = "Get all users",
            description = "Returns a paginated list of users with optional filters",
            security = @SecurityRequirement(name = "Bearer Authentication"),
            parameters = {
                    @Parameter(name = "page", description = "Page number (0-based)", schema = @Schema(defaultValue = "0")),
                    @Parameter(name = "size", description = "Page size (max 100)", schema = @Schema(defaultValue = "20")),
                    @Parameter(name = "sortBy", description = "Sort field", schema = @Schema(defaultValue = "id")),
                    @Parameter(name = "sortDir", description = "Sort direction (asc/desc)", schema = @Schema(defaultValue = "asc")),
                    @Parameter(name = "username", description = "Username filter (exact match or use 'contains:' prefix for partial match)"),
                    @Parameter(name = "email", description = "Email filter (exact match or use 'contains:' prefix for partial match)"),
                    @Parameter(name = "role", description = "Role filter (exact match)"),
                    @Parameter(name = "createdAfter", description = "Filter users created after this date (ISO 8601 format)"),
                    @Parameter(name = "createdBefore", description = "Filter users created before this date (ISO 8601 format)")
            }
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Users retrieved successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request parameters"),
            @ApiResponse(responseCode = "403", description = "Access denied - Admin role required")
    })
    public ResponseEntity<Page<UserDTO>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "id") String sortBy,
            @RequestParam(defaultValue = "asc") String sortDir,
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String role,
            @RequestParam(required = false) String createdAfter,
            @RequestParam(required = false) String createdBefore) {

        // Date validation
        if (createdAfter != null && !isValidISODate(createdAfter)) {
            throw new IllegalArgumentException("createdAfter must be in ISO 8601 format");
        }
        if (createdBefore != null && !isValidISODate(createdBefore)) {
            throw new IllegalArgumentException("createdBefore must be in ISO 8601 format");
        }

        Sort sort = Sort.by(sortDir.equalsIgnoreCase("desc") ? Sort.Direction.DESC : Sort.Direction.ASC, sortBy);
        Pageable pageable = PageRequest.of(page, Math.min(size, 100), sort);

        List<U> users = userService.getAllUsers(pageable, username, email, role, createdAfter, createdBefore);
        List<UserDTO> userDTOs = users.stream().map(UserDTOMapper::toDTO).toList();
        Page<UserDTO> pagedUserDTOs = new PageImpl<>(userDTOs, pageable, users.size());
        return ResponseEntity.ok(pagedUserDTOs);
    }

    @GetMapping("/search")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
            summary = "Search users",
            description = "Search users by username or email",
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Search completed successfully"),
            @ApiResponse(responseCode = "403", description = "Access denied - Admin role required")
    })
    public ResponseEntity<Page<UserDTO>> searchUsers(
            @RequestParam String query,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "id") String sortBy,
            @RequestParam(defaultValue = "asc") String sortDir) {

        Sort sort = Sort.by(sortDir.equalsIgnoreCase("desc") ? Sort.Direction.DESC : Sort.Direction.ASC, sortBy);
        Pageable pageable = PageRequest.of(page, Math.min(size, 100), sort);

        List<U> users = userService.searchUsers(query, pageable);
        List<UserDTO> userDTOs = users.stream()
                .map(UserDTOMapper::toDTO).toList();

        Page<UserDTO> pagedUserDTOs = new PageImpl<>(userDTOs, pageable, users.size());

        return ResponseEntity.ok(pagedUserDTOs);
    }

    // TODO - REMOVE THIS
    @GetMapping("/metrics/db-operations")
    public List<DatabaseOperation> getDatabaseOperations() {
        return metricsCollector.getOperations();
    }


    private boolean isValidISODate(String date) {
        try {
            java.time.Instant.parse(date);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}