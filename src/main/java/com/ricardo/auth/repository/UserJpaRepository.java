package com.ricardo.auth.repository;

import com.ricardo.auth.domain.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

import java.util.Optional;

/**
 * JPA repository for User entities.
 * This provides the concrete implementation of UserRepository for User entities.
 *
 * @param <U>  the type parameter
 * @param <ID> the type parameter
 */
@NoRepositoryBean
public interface UserJpaRepository<U extends AuthUser<?>, ID> extends UserRepository<U, ID>, JpaRepository<U, ID> {
    /**
     * Find by email email optional.
     *
     * @param email the email
     * @return the optional
     */
    Optional<U> findByEmail_Email(String email);

    /**
     * Find by username username optional.
     *
     * @param username the username
     * @return the optional
     */
    Optional<U> findByUsername_Username(String username);

    /**
     * Exists by email email boolean.
     *
     * @param email the email
     * @return the boolean
     */
    boolean existsByEmail_Email(String email);

    /**
     * Exists by username username boolean.
     *
     * @param username the username
     * @return the boolean
     */
    boolean existsByUsername_Username(String username);

    @Override
    default Optional<U> findByEmail(String email) {
        return findByEmail_Email(email);
    }

    @Override
    default Optional<U> findByUsername(String username) {
        return findByUsername_Username(username);
    }

    @Override
    default boolean existsByEmail(String email) {
        return existsByEmail_Email(email);
    }

    @Override
    default boolean existsByUsername(String username) {
        return existsByUsername_Username(username);
    }
}