package com.ricardo.auth.core;

import com.ricardo.auth.domain.AuthUser;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;

public interface UserService<U extends AuthUser<?>, ID> {

    U getUserById(ID id);

    U createUser(U user);

    U updateUser(ID id, U userDetails);

    void deleteUser(ID id);

    boolean userExists(String email);

    U getUserByEmail(String email);

    List<U> getAllUsers();

    Optional<U> authenticate(String email, String rawPassword, PasswordEncoder encoder);
}