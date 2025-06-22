package com.ricardo.auth.controller;

import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.*;
import com.ricardo.auth.dto.CreateUserRequestDTO;
import com.ricardo.auth.dto.UserDTO;
import com.ricardo.auth.dto.UserDTOMapper;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

/**
 * The type User controller.
 */
@RestController
@RequestMapping("/api/users")
@ConditionalOnMissingBean(UserApiEndpoint.class)
public class UserController implements UserApiEndpoint {
    private final PasswordEncoder passwordEncoder;
    private final UserService<User, Long> userService;

    /**
     * Instantiates a new User controller.
     *
     * @param userService     the user service
     * @param passwordEncoder the password encoder
     */
    public UserController(UserService<User, Long> userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Create user response entity.
     *
     * @param request the request
     * @return the response entity
     */
    @PostMapping("/create")
    public ResponseEntity<UserDTO> createUser(@RequestBody CreateUserRequestDTO request) {
        Username name = Username.valueOf(request.getUsername());
        Email email = Email.valueOf(request.getEmail());
        Password password = Password.valueOf(request.getPassword(), passwordEncoder);

        User user = new User(name, email, password);
        user.addRole(AppRole.USER);
        User createdUser = userService.createUser(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(UserDTOMapper.toDTO(createdUser));
    }

    /**
     * Gets user by email.
     *
     * @param email the email
     * @return the user by email
     */
    @GetMapping("/email/{email}")
    public ResponseEntity<UserDTO> getUserByEmail(@PathVariable String email) {
        User user = userService.getUserByEmail(email);
        return ResponseEntity.ok(UserDTOMapper.toDTO(user));
    }

    /**
     * Gets user by id.
     *
     * @param id the id
     * @return the user by id
     */
    @GetMapping("/{id}")
    public ResponseEntity<UserDTO> getUserById(@PathVariable Long id) {
        User user = userService.getUserById(id);
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
     * @param request the request
     * @param id      the id
     * @return the response entity
     */
    @PutMapping("/update/{id}")
    public ResponseEntity<UserDTO> updateUser(@RequestBody CreateUserRequestDTO request, @PathVariable Long id) {
        Username name = Username.valueOf(request.getUsername());
        Email email = Email.valueOf(request.getEmail());
        Password passwordInstance = Password.valueOf(request.getPassword(), passwordEncoder);

        User userDetails = new User(name, email, passwordInstance);
        User updatedUser = userService.updateUser(id, userDetails);
        return ResponseEntity.ok(UserDTOMapper.toDTO(updatedUser));
    }

    /**
     * Delete user response entity.
     *
     * @param id the id
     * @return the response entity
     */
    @DeleteMapping("/delete/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}