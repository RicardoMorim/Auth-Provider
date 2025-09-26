package com.ricardo.auth.repository.user;


import com.ricardo.auth.core.Role;
import com.ricardo.auth.domain.user.AuthUser;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.NoRepositoryBean;

import java.util.List;
import java.util.Optional;

/**
 * Base repository interface for authentication user operations.
 * Custom user repositories should extend this interface.
 *
 * @param <U>  The user entity type, which must implement AuthUser.
 * @param <R>  the type parameter
 * @param <ID> The user entity ID type.
 */
@NoRepositoryBean
public interface UserRepository<U extends AuthUser<ID, R>, R extends Role, ID> {
    /**
     * Find by email optional.
     *
     * @param email the email
     * @return the optional
     */
    Optional<U> findByEmail(String email);

    /**
     * Find by username optional.
     *
     * @param username the username
     * @return the optional
     */
    Optional<U> findByUsername(String username);

    /**
     * Exists by email boolean.
     *
     * @param email the email
     * @return the boolean
     */
    boolean existsByEmail(String email);

    /**
     * Exists by username boolean.
     *
     * @param username the username
     * @return the boolean
     */
    boolean existsByUsername(String username);

    /**
     * Find by id optional.
     *
     * @param id the id
     * @return the optional
     */
    Optional<U> findById(ID id);

    /**
     * Exists by id boolean.
     *
     * @param id the id
     * @return the boolean
     */
    boolean existsById(ID id);

    /**
     * Save user s.
     *
     * @param <S>    the type parameter
     * @param entity the entity
     * @return the s
     */
    <S extends U> S saveUser(S entity);

    /**
     * Save all list.
     *
     * @param <S>      the type parameter
     * @param entities the entities
     * @return the list
     */
    <S extends U> List<S> saveAll(Iterable<S> entities);

    /**
     * Find all list.
     *
     * @return the list
     */
    List<U> findAll();

    /**
     * Find all by id list.
     *
     * @param ids the ids
     * @return the list
     */
    List<U> findAllById(Iterable<ID> ids);

    /**
     * Count long.
     *
     * @return the long
     */
    long count();

    /**
     * Delete by id.
     *
     * @param id the id
     */
    void deleteById(ID id);

    /**
     * Delete.
     *
     * @param entity the entity
     */
    void delete(U entity);

    /**
     * Delete all by id.
     *
     * @param ids the ids
     */
    void deleteAllById(Iterable<? extends ID> ids);

    /**
     * Delete all.
     *
     * @param entities the entities
     */
    void deleteAll(Iterable<? extends U> entities);

    /**
     * Delete all.
     */
    void deleteAll();

    /**
     * Count users by role int.
     *
     * @param Role the role
     * @return the int
     */
    int countUsersByRole(String Role);

    /**
     * Count users int.
     *
     * @return the int
     */
    int countUsers();


    /**
     * Find all users with pagination
     *
     * @param pageable the pageable
     * @return the page
     */
    Page<U> findAll(Pageable pageable);

    /**
     * Find users with filters and pagination
     *
     * @param username      the username
     * @param email         the email
     * @param roleList      the role list
     * @param createdAfter  the created after
     * @param createdBefore the created before
     * @param pageable      the pageable
     * @return the page
     */
    Page<U> findAllWithFilters(String username, String email, java.util.List<String> roleList,
                               java.time.Instant createdAfter, java.time.Instant createdBefore,
                               Pageable pageable);


    /**
     * Search users by query with pagination
     *
     * @param query    the query
     * @param pageable the pageable
     * @return the page
     */
    Page<U> searchByQuery(String query, Pageable pageable);

}