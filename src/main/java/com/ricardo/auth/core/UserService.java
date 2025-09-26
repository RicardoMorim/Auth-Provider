package com.ricardo.auth.core;

import com.ricardo.auth.domain.user.AuthUser;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;

/**
 * The interface User service.
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 *
 * @param <U>  the type parameter
 * @param <R>  the type parameter
 * @param <ID> the type parameter
 */
public interface UserService<U extends AuthUser<ID, R>, R extends Role, ID> {

    /**
     * Delete all users.
     */
    void deleteAllUsers();

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
     * Update username and email u.
     *
     * @param id       the id
     * @param email    the email
     * @param username the username
     * @return the u
     */
    U updateEmailAndUsername(ID id, String email, String username);

    /**
     * Update password u.
     *
     * @param id       the id
     * @param password the password
     * @return the u
     */
    U updatePassword(ID id, String password);

    /**
     * Update user u.
     *
     * @param id   the id
     * @param user the user
     * @return the u
     */
    U updateUser(ID id, U user);

    /**
     * Delete user.
     *
     * @param id the id
     */
    void deleteUser(ID id);

    /**
     * Delete user by username.
     *
     * @param username the username
     */
    void deleteUserByUsername(String username);

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
     * @param pageable      the pageable
     * @param username      the username
     * @param email         the email
     * @param role          the role
     * @param createdAfter  the created after
     * @param createdBefore the created before
     * @return the all users
     */
    List<U> getAllUsers(Pageable pageable, String username, String email,
                        String role, String createdAfter, String createdBefore);

    /**
     * Search users list.
     *
     * @param query    the query
     * @param pageable the pageable
     * @return the list
     */
    List<U> searchUsers(String query, Pageable pageable);

    /**
     * Authenticate optional.
     *
     * @param email       the email
     * @param rawPassword the raw password
     * @param encoder     the encoder
     * @return the optional
     */
    Optional<U> authenticate(String email, String rawPassword, PasswordEncoder encoder);

    /**
     * Gets user by user name.
     *
     * @param userName the user name
     * @return the user by user name
     */
    U getUserByUserName(String userName);

    /**
     * Count admins int.
     *
     * @return the int
     */
    int countAdmins();
}