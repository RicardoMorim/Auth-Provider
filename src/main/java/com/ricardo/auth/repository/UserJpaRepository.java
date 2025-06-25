package com.ricardo.auth.repository;

import com.ricardo.auth.domain.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * JPA repository for User entities.
 * This provides the concrete implementation of UserRepository for User entities.
 */
@Repository
public interface UserJpaRepository<U extends AuthUser<?>, ID> extends UserRepository<U, ID>, JpaRepository<U, ID> {
    // JPA generated methods
    Optional<U> findByEmail_Email(String email);
    Optional<U> findByUsername_Username(String username);
    boolean existsByEmail_Email(String email);
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