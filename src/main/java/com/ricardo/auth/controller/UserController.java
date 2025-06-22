package com.ricardo.auth.controller;

import com.ricardo.auth.core.AuthUser;
import com.ricardo.auth.domain.Email;
import com.ricardo.auth.domain.Password;
import com.ricardo.auth.domain.User;
import com.ricardo.auth.domain.Username;
import com.ricardo.auth.dto.CreateUserRequestDTO;
import com.ricardo.auth.dto.UserDTO;
import com.ricardo.auth.dto.UserDTOMapper;
import com.ricardo.auth.core.UserService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final PasswordEncoder passwordEncoder;
    private final UserService<User, Long> userService;

    public UserController(UserService<User, Long> userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/create")
    public UserDTO createUser(@RequestBody CreateUserRequestDTO request) {
        Username name = Username.valueOf(request.getUsername());
        Email email = Email.valueOf(request.getEmail());
        Password password = Password.valueOf(request.getPassword(), passwordEncoder);

        User user = new User(name, email, password);
        user.addRole(AuthUser.Role.USER);
        User createdUser = userService.createUser(user);
        return UserDTOMapper.toDTO(createdUser);
    }

    @GetMapping("/email/{email}")
    public UserDTO getUserByEmail(@PathVariable String email) {
        User user = userService.getUserByEmail(email);
        return UserDTOMapper.toDTO(user);
    }

    @GetMapping("/{id}")
    public UserDTO getUserById(@PathVariable Long id) {
        User user = userService.getUserById(id);
        return UserDTOMapper.toDTO(user);
    }

    @GetMapping("/exists/{email}")
    public boolean userExists(@PathVariable String email) {
        return userService.userExists(email);
    }

    @PutMapping("/update/{id}")
    public UserDTO updateUser(@RequestBody CreateUserRequestDTO request, @PathVariable Long id) {
        Username name = Username.valueOf(request.getUsername());
        Email email = Email.valueOf(request.getEmail());
        Password passwordInstance = Password.valueOf(request.getPassword(), passwordEncoder);

        User userDetails = new User(name, email, passwordInstance);
        User updatedUser = userService.updateUser(id, userDetails);
        return UserDTOMapper.toDTO(updatedUser);
    }

    @DeleteMapping("/delete/{id}")
    public void deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
    }
}