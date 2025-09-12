package com.ricardo.auth.core;

import com.ricardo.auth.domain.user.AuthUser;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;

/**
 * The interface User service.
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 *
 * @param <U>  the type parameter
 * @param <ID> the type parameter
 */
public interface UserService<U extends AuthUser<ID, R>, R extends Role, ID> {

    /**
     * Gets user by id.
     *
     * @param id the id
     * @return the user by id
     */
    U getUserById(ID id);

    /**
     * Create user u.
     *
     * @param user the user
     * @return the u
     */
    U createUser(U user);

    /**
     * Update user u.
     *
     * @param id          the id
     * @param userDetails the user details
     * @return the u
     */
    U updateUser(ID id, U userDetails);

    /**
     * Delete user.
     *
     * @param id the id
     */
    void deleteUser(ID id);

    /**
     * User exists boolean.
     *
     * @param email the email
     * @return the boolean
     */
    boolean userExists(String email);

    /**
     * Gets user by email.
     *
     * @param email the email
     * @return the user by email
     */
    U getUserByEmail(String email);

    /**
     * Gets all users.
     *
     * @return the all users
     */
    List<U> getAllUsers();

    /**
     * Authenticate optional.
     *
     * @param email       the email
     * @param rawPassword the raw password
     * @param encoder     the encoder
     * @return the optional
     */
    Optional<U> authenticate(String email, String rawPassword, PasswordEncoder encoder);

    U getUserByUserName(String userName);

    int countAdmins();
}