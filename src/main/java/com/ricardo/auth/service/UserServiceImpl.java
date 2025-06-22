package com.ricardo.auth.service;

import com.ricardo.auth.core.AuthUser;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl<U extends AuthUser<?>, ID> implements UserService<U, ID> {

    private final UserRepository<U, ID> userRepository;

    // A implementação concreta do repositório será injetada pelo Spring
    public UserServiceImpl(UserRepository<U, ID> userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public U getUserById(ID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + id));
    }

    @Override
    public U createUser(U user) {
        if (userRepository.existsByEmail(user.getEmail())) {
            throw new RuntimeException("Email already exists: " + user.getEmail());
        }
        return userRepository.save(user);
    }

    @Override
    public U updateUser(ID id, U userDetails) {
        U user = getUserById(id);
        // Atualiza os campos com base na interface AuthUser
        user.setUsername(userDetails.getUsername());
        user.setEmail(userDetails.getEmail());
        if (userDetails.getPassword() != null && !userDetails.getPassword().isEmpty()) {
            user.setPassword(userDetails.getPassword());
        }
        return userRepository.save(user);
    }

    @Override
    public void deleteUser(ID id) {
        userRepository.deleteById(id);
    }

    @Override
    public boolean userExists(String email) {
        return userRepository.existsByEmail(email);
    }

    @Override
    public U getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with email: " + email));
    }

    @Override
    public List<U> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public Optional<U> authenticate(String email, String rawPassword, PasswordEncoder encoder) {
        return userRepository.findByEmail(email)
                .filter(user -> encoder.matches(rawPassword, user.getPassword()));
    }
}