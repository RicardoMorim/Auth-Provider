package com.ricardo.auth.repository;

import com.ricardo.auth.domain.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.NoRepositoryBean;

import java.util.Optional;

/**
 * Interface de repositório base para operações de utilizador de autenticação.
 * Os repositórios de utilizador personalizados devem estender esta interface.
 *
 * @param <U>  O tipo da entidade do utilizador, que deve implementar AuthUser.
 * @param <ID> O tipo do ID da entidade do utilizador.
 */
@NoRepositoryBean
public interface UserRepository<U extends AuthUser<?>, ID> extends JpaRepository<U, ID> {

    /**
     * Find by email string (queries the embedded Email object's email field).
     *
     * @param email the email string
     * @return the optional user
     */
    @Query("SELECT u FROM #{#entityName} u WHERE u.email.email = :email")
    Optional<U> findByEmail(String email);

    /**
     * Check if user exists by email string.
     *
     * @param email the email string
     * @return true if exists
     */
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM #{#entityName} u WHERE u.email.email = :email")
    boolean existsByEmail(String email);
}