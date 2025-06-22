package com.ricardo.auth.repository;

import com.ricardo.auth.domain.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
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
     * Find by email optional.
     *
     * @param email the email
     * @return the optional
     */
    Optional<U> findByEmail(String email);

    /**
     * Exists by email boolean.
     *
     * @param email the email
     * @return the boolean
     */
    boolean existsByEmail(String email);
}