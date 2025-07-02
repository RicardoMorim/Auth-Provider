package com.ricardo.auth.service;

import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.domain.exceptions.DuplicateResourceException;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import com.ricardo.auth.repository.user.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;

/**
 * The type User service.
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 *
 * @param <U>  the type parameter
 * @param <ID> the type parameter
 */
public class UserServiceImpl<U extends AuthUser<?>, ID> implements UserService<U, ID> {

    private final UserRepository<U, ID> userRepository;

    /**
     * Instantiates a new User service.
     *
     * @param userRepository the user repository
     */
    public UserServiceImpl(UserRepository<U, ID> userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public U getUserById(ID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));
    }

    @Override
    public U createUser(U user) {
        if (userRepository.existsByEmail(user.getEmail())) {
            throw new DuplicateResourceException("Email already exists: " + user.getEmail());
        }
        return userRepository.save(user);
    }

    @Override
    public U updateUser(ID id, U userDetails) {
        U user = getUserById(id);
        user.setUsername(userDetails.getUsername());
        user.setEmail(userDetails.getEmail());
        if (userDetails.getPassword() != null && !userDetails.getPassword().isEmpty()) {
            user.setPassword(userDetails.getPassword());
        }
        return userRepository.save(user);
    }

    @Override
    public void deleteUser(ID id) {
        if (!userRepository.existsById(id)) {
            throw new ResourceNotFoundException("User not found with id: " + id);
        }
        userRepository.deleteById(id);
    }

    @Override
    public boolean userExists(String email) {
        return userRepository.existsByEmail(email);
    }

    @Override
    public U getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));
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