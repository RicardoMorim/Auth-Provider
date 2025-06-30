package com.ricardo.auth.repository;


import com.ricardo.auth.domain.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

import java.util.Optional;

/**
 * Base repository interface for authentication user operations.
 * Custom user repositories should extend this interface.
 *
 * @param <U>  The user entity type, which must implement AuthUser.
 * @param <ID> The user entity ID type.
 */
@NoRepositoryBean
public interface UserRepository<U extends AuthUser<?>, ID> extends JpaRepository<U, ID> {

    /**
     * Find by email string (queries the embedded Email object's email field).
     * Implementation could use JPA generated methods (these are just for naming consistency).
     *
     * @param email the email string
     * @return the optional user
     */
    Optional<U> findByEmail(String email);

    /**
     * Find by username string (queries the embedded Username object's username field).
     * Implementation could use JPA generated methods (these are just for naming consistency).
     *
     * @param username the username string
     * @return the optional user
     */
    Optional<U> findByUsername(String username);

    /**
     * Check if user exists by email string.
     * Implementation could use JPA generated methods (these are just for naming consistency).
     *
     * @param email the email string
     * @return true if exists
     */
    boolean existsByEmail(String email);

    /**
     * Check if user exists by username string.
     * Implementation could use JPA generated methods (these are just for naming consistency).
     *
     * @param username the username string
     * @return true if exists
     */
    boolean existsByUsername(String username);
}