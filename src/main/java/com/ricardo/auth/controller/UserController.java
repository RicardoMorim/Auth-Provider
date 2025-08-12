package com.ricardo.auth.controller;

import com.ricardo.auth.core.Role;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.dto.CreateUserRequestDTO;
import com.ricardo.auth.dto.UserDTO;
import com.ricardo.auth.dto.UserDTOMapper;
import com.ricardo.auth.factory.AuthUserFactory;
import com.ricardo.auth.helper.IdConverter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * The type User controller.
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 */
@RestController
@RequestMapping("/api/users")
public class UserController<U extends AuthUser<ID, R>, R extends Role, ID> implements UserApiEndpoint {
    private final UserService<U, R, ID> userService;
    private final AuthUserFactory<U, R, ID> userBuilder;
    private final IdConverter<ID> idConverter;

    /**
     * Instantiates a new User controller.
     *
     * @param userService the user service
     * @param userBuilder the user builder
     */
    public UserController(UserService<U, R, ID> userService, AuthUserFactory<U, R, ID> userBuilder, IdConverter<ID> idConverter) {
        this.userService = userService;
        this.userBuilder = userBuilder;
        this.idConverter = idConverter;
    }

    /**
     * Create user response entity.
     *
     * @param request the request
     * @return the response entity
     */
    @PostMapping("/create")
    public ResponseEntity<UserDTO> createUser(@RequestBody CreateUserRequestDTO request) {
        U user = userBuilder.create(request);

        U newUser = userService.createUser(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(UserDTOMapper.toDTO(newUser));
    }

    /**
     * Gets user by email.
     *
     * @param email the email
     * @return the user by email
     */
    @GetMapping("/email/{email}")
    public ResponseEntity<UserDTO> getUserByEmail(@PathVariable String email) {
        U user = userService.getUserByEmail(email);
        return ResponseEntity.ok(UserDTOMapper.toDTO(user));
    }

    /**
     * Gets user by id.
     *
     * @param id the id
     * @return the user by id
     */
    @GetMapping("/{stringId}")
    public ResponseEntity<UserDTO> getUserById(@PathVariable String stringId) {
        ID id = idConverter.fromString(stringId);
        U user = userService.getUserById(id);
        return ResponseEntity.ok(UserDTOMapper.toDTO(user));
    }

    /**
     * User exists response entity.
     *
     * @param email the email
     * @return the response entity
     */
    @GetMapping("/exists/{email}")
    public ResponseEntity<Boolean> userExists(@PathVariable String email) {
        boolean exists = userService.userExists(email);
        return ResponseEntity.ok(exists);
    }

    /**
     * Update user response entity.
     *
     * @param request        the request
     * @param stringId             the id
     * @param authentication the authentication
     * @return the response entity
     */
    @PutMapping("/update/{id}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurityService.isOwner(authentication.name, #stringId)")
    public ResponseEntity<UserDTO> updateUser(@RequestBody CreateUserRequestDTO request, @PathVariable("id") String stringId, Authentication authentication) {
        ID id = idConverter.fromString(stringId);
        U userDetails = userBuilder.create(request);
        U updatedUser = userService.updateUser(id, userDetails);
        return ResponseEntity.ok(UserDTOMapper.toDTO(updatedUser));
    }

    /**
     * Delete user response entity.
     *
     * @param stringId             the id
     * @param authentication the authentication
     * @return the response entity
     */
    @DeleteMapping("/delete/{stringId}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurityService.isOwner(authentication.name, #stringId)")
    public ResponseEntity<Void> deleteUser(@PathVariable String stringId, Authentication authentication) {
        ID id = idConverter.fromString(stringId);

        U user = userService.getUserById(id);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        userService.deleteUser(id);
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