package com.ricardo.auth.controller;

import com.ricardo.auth.domain.*;
import com.ricardo.auth.dto.CreateUserRequestDTO;
import com.ricardo.auth.dto.UserDTO;
import com.ricardo.auth.dto.UserDTOMapper;
import com.ricardo.auth.core.UserService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@ConditionalOnMissingBean(UserApiEndpoint.class)
public class UserController implements UserApiEndpoint {
    private final PasswordEncoder passwordEncoder;
    private final UserService<User, Long> userService;

    public UserController(UserService<User, Long> userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

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

    @GetMapping("/email/{email}")
    public ResponseEntity<UserDTO> getUserByEmail(@PathVariable String email) {
        User user = userService.getUserByEmail(email);
        return ResponseEntity.ok(UserDTOMapper.toDTO(user));
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserDTO> getUserById(@PathVariable Long id) {
        User user = userService.getUserById(id);
        return ResponseEntity.ok(UserDTOMapper.toDTO(user));
    }

    @GetMapping("/exists/{email}")
    public ResponseEntity<Boolean> userExists(@PathVariable String email) {
        boolean exists = userService.userExists(email);
        return ResponseEntity.ok(exists);
    }

    @PutMapping("/update/{id}")
    public ResponseEntity<UserDTO> updateUser(@RequestBody CreateUserRequestDTO request, @PathVariable Long id) {
        Username name = Username.valueOf(request.getUsername());
        Email email = Email.valueOf(request.getEmail());
        Password passwordInstance = Password.valueOf(request.getPassword(), passwordEncoder);

        User userDetails = new User(name, email, passwordInstance);
        User updatedUser = userService.updateUser(id, userDetails);
        return ResponseEntity.ok(UserDTOMapper.toDTO(updatedUser));
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}