package com.ricardo.auth.repository.user;

import com.ricardo.auth.core.Role;
import com.ricardo.auth.domain.user.AuthUser;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * JPA repository for User entities.
 * This provides the concrete implementation of UserRepository for User entities.
 *
 * @param <U>  the type parameter
 * @param <R>  the type parameter
 * @param <ID> the type parameter
 */
@NoRepositoryBean
public interface UserJpaRepository<U extends AuthUser<ID, R>, R extends Role, ID> extends UserRepository<U, R, ID>, JpaRepository<U, ID> {

    /**
     * Find by email email optional.
     *
     * @param email the email
     * @return the optional
     */
    @Query("SELECT u FROM #{#entityName} u LEFT JOIN FETCH u.roles WHERE u.email.email = :email")
    Optional<U> findByEmail_Email(String email);

    /**
     * Find by username username optional.
     *
     * @param username the username
     * @return the optional
     */
    @Query("SELECT u FROM #{#entityName} u LEFT JOIN FETCH u.roles WHERE u.username.username = :username")
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
    default Optional<U> findByUsername(String username) {
        return findByUsernameWithRoles(username);
    }

    @Override
    default Optional<U> findByEmail(String email) {
        return findByEmailWithRoles(email);
    }


    @Override
    default boolean existsByEmail(String email) {
        return existsByEmail_Email(email);
    }

    @Override
    default boolean existsByUsername(String username) {
        return existsByUsername_Username(username);
    }

    @Override
    default <S extends U> S saveUser(S entity) {
        return save(entity);
    }

    @Override
    default int countUsers() {
        return Math.toIntExact(count());
    }


    /**
     * Count by roles long.
     *
     * @param roleName the role name
     * @return the long
     */
    long countByRoles(String roleName);

    /**
     * Count by roles ignore case long.
     *
     * @param roleName the role name
     * @return the long
     */
    @org.springframework.data.jpa.repository.Query(
            "select count(u) from #{#entityName} u join u.roles r where lower(cast(r as string)) = lower(:roleName)"
    )
    long countByRolesIgnoreCase(@org.springframework.data.repository.query.Param("roleName") String roleName);

    default int countUsersByRole(String role) {
        return (int) countByRoles(role);
    }

    @Override
    @Query("SELECT DISTINCT u FROM #{#entityName} u LEFT JOIN u.roles r WHERE " +
            "(:username IS NULL OR u.username.username LIKE CONCAT('%', :username, '%')) AND " +
            "(:email IS NULL OR u.email.email LIKE CONCAT('%', :email, '%')) AND " +
            "(:roleList IS NULL OR EXISTS (SELECT 1 FROM #{#entityName} u2 JOIN u2.roles r2 WHERE u2.id = u.id AND r2 IN :roleList)) AND " +
            "(:createdAfter IS NULL OR u.createdAt >= :createdAfter) AND " +
            "(:createdBefore IS NULL OR u.createdAt <= :createdBefore)")
    Page<U> findAllWithFilters(
            @Param("username") String username,
            @Param("email") String email,
            @Param("roleList") List<String> roleList,
            @Param("createdAfter") Instant createdAfter,
            @Param("createdBefore") Instant createdBefore,
            Pageable pageable);

    @Override
    @Query("SELECT u FROM #{#entityName} u WHERE " +
            "u.username.username LIKE %:query% OR u.email.email LIKE %:query%")
    Page<U> searchByQuery(@Param("query") String query, Pageable pageable);


    /**
     * Find by username with roles optional.
     *
     * @param username the username
     * @return the optional
     */
    @Query("SELECT u FROM #{#entityName} u LEFT JOIN FETCH u.roles WHERE u.username.username = :username")
    Optional<U> findByUsernameWithRoles(@Param("username") String username);


    /**
     * Find by email with roles optional.
     *
     * @param email the email
     * @return the optional
     */
    @Query("SELECT u FROM #{#entityName} u LEFT JOIN FETCH u.roles WHERE u.email.email = :email")
    Optional<U> findByEmailWithRoles(@Param("email") String email);

}