package com.ricardo.auth.repository;

import com.ricardo.auth.domain.User;
import org.springframework.stereotype.Repository;

/**
 * JPA repository for User entities.
 * This provides the concrete implementation of UserRepository for User entities.
 */
@Repository
public interface UserJpaRepository extends UserRepository<User, Long> {
    // All methods are inherited from UserRepository and JpaRepository
    // Spring Data JPA will automatically provide implementations
}
