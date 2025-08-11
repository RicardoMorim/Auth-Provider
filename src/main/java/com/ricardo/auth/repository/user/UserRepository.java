package com.ricardo.auth.repository.user;


import com.ricardo.auth.core.Role;
import com.ricardo.auth.domain.user.AuthUser;
import org.springframework.data.repository.NoRepositoryBean;

import java.util.List;
import java.util.Optional;

/**
 * Base repository interface for authentication user operations.
 * Custom user repositories should extend this interface.
 *
 * @param <U>  The user entity type, which must implement AuthUser.
 * @param <ID> The user entity ID type.
 */
@NoRepositoryBean
public interface UserRepository<U extends AuthUser<ID, R>, R extends Role, ID> {
    Optional<U> findByEmail(String email);

    Optional<U> findByUsername(String username);

    boolean existsByEmail(String email);

    boolean existsByUsername(String username);

    Optional<U> findById(ID id);

    boolean existsById(ID id);

    <S extends U> S saveUser(S entity);

    <S extends U> List<S> saveAll(Iterable<S> entities);

    List<U> findAll();

    List<U> findAllById(Iterable<ID> ids);

    long count();

    void deleteById(ID id);

    void delete(U entity);

    void deleteAllById(Iterable<? extends ID> ids);

    void deleteAll(Iterable<? extends U> entities);

    void deleteAll();
    // Optionally add pagination and sorting signatures if needed, but not required for JdbcTemplate
}