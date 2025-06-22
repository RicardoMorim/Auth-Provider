package com.ricardo.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;
import com.ricardo.auth.domain.AuthUser;

import java.util.Optional;

/**
 * Interface de repositório base para operações de utilizador de autenticação.
 * Os repositórios de utilizador personalizados devem estender esta interface.
 *
 * @param <U> O tipo da entidade do utilizador, que deve implementar AuthUser.
 * @param <ID> O tipo do ID da entidade do utilizador.
 */
@NoRepositoryBean
public interface UserRepository<U extends AuthUser<?>, ID> extends JpaRepository<U, ID> {

    Optional<U> findByEmail(String email);

    boolean existsByEmail(String email);
}