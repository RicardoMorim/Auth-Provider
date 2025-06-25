package com.ricardo.auth.repository;

import com.ricardo.auth.domain.AuthUser;
import com.ricardo.auth.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Interface de repositório base para a classe User.
 * Se usar outra entidade, deve criar uma interface específica que estenda UserJpaRepository.
 */
@Repository
public interface DefaultUserJpaRepository extends UserJpaRepository<User, Long> {
}