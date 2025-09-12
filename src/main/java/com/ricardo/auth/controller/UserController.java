package com.ricardo.auth.controller;

import com.ricardo.auth.core.Role;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.dto.CreateUserRequestDTO;
import com.ricardo.auth.dto.UserDTO;
import com.ricardo.auth.dto.UserDTOMapper;
import com.ricardo.auth.factory.AuthUserFactory;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * The type User controller.
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 */
@RestController
@RequestMapping("/api/users")
@Validated
@Tag(name = "User Management", description = "User CRUD operations")
public class UserController<U extends AuthUser<ID, R>, R extends Role, ID> implements UserApiEndpoint {
    private final UserService<U, R, ID> userService;
    private final AuthUserFactory<U, R, ID> userBuilder;
    private final IdConverter<ID> idConverter;

    /**
     * Instantiates a new User controller.
     *
     * @param userService the user service
     * @param userBuilder the user builder
     * @param idConverter the id converter
     */
    public UserController(UserService<U, R, ID> userService, AuthUserFactory<U, R, ID> userBuilder, IdConverter<ID> idConverter) {
        this.userService = userService;
        this.userBuilder = userBuilder;
        this.idConverter = idConverter;
    }

    /**
     * Create user response entity.
     * Only admins can create users to prevent unauthorized registration.
     *
     * @param request the request
     * @return the response entity
     */
    @Operation(
            summary = "Create new user",
            description = "Create a new user. Only accessible by administrators.",
            security = @SecurityRequirement(name = "CookieAuth")
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "User created successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UserDTO.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid request or validation error",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access denied - admin role required",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "User already exists",
                    content = @Content(mediaType = "application/json")
            )
    })
    @PostMapping("/create")
    public ResponseEntity<UserDTO> createUser(
            @Parameter(description = "User creation request", required = true)
            @Valid @RequestBody CreateUserRequestDTO request) {
        U user = userBuilder.create(request);

        U newUser = userService.createUser(user);

        return ResponseEntity.status(HttpStatus.CREATED).body(UserDTOMapper.toDTO(newUser));
    }

    /**
     * Gets user by email.
     * Only admins can lookup users by email to prevent user enumeration.
     *
     * @param email the email
     * @return the user by email
     */
    @Operation(
            summary = "Get user by email",
            description = "Retrieve user information by email address. Only accessible by administrators.",
            security = @SecurityRequirement(name = "CookieAuth")
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "User found",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UserDTO.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access denied - admin role required",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "User not found",
                    content = @Content(mediaType = "application/json")
            )
    })
    @GetMapping("/email/{email}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserDTO> getUserByEmail(
            @Parameter(description = "User email address", required = true)
            @PathVariable String email) {
        U user = userService.getUserByEmail(email);
        return ResponseEntity.ok(UserDTOMapper.toDTO(user));
    }

    /**
     * Gets user by id.
     * Only admins or the user themselves can access user data.
     *
     * @param username the id
     * @return the user by id
     */
    @GetMapping("/{username}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurityService.isOwnerUsername(authentication.name, #username)")
    public ResponseEntity<UserDTO> getUserById(@PathVariable String username) {
        U user = userService.getUserByUserName(username);
        return ResponseEntity.ok(UserDTOMapper.toDTO(user));
    }

    /**
     * User exists response entity.
     * Only admins can check if users exist to prevent user enumeration.
     *
     * @param email the email
     * @return the response entity
     */
    @GetMapping("/exists/{email}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Boolean> userExists(@PathVariable String email) {
        boolean exists = userService.userExists(email);
        return ResponseEntity.ok(exists);
    }

    /**
     * Update user response entity.
     *
     * @param request        the request
     * @param username       the id
     * @param authentication the authentication
     * @return the response entity
     */
    @PutMapping("/update/{username}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurityService.isOwnerUsername(authentication.name, #username)")
    public ResponseEntity<UserDTO> updateUser(@Valid @RequestBody CreateUserRequestDTO request, @PathVariable("username") String username, Authentication authentication) {
        ID id = userService.getUserByUserName(username).getId();
        U userDetails = userBuilder.create(request);
        U updatedUser = userService.updateUser(id, userDetails);

        return ResponseEntity.ok(UserDTOMapper.toDTO(updatedUser));
    }

    /**
     * Delete user response entity.
     *
     * @param username       the id
     * @param authentication the authentication
     * @return the response entity
     */
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
    public ResponseEntity<List<UserDTO>> getAllUsers() {
        List<U> users = userService.getAllUsers();
        List<UserDTO> dtos = users.stream().map(UserDTOMapper::toDTO).toList();
        return ResponseEntity.ok(dtos);
    }
}