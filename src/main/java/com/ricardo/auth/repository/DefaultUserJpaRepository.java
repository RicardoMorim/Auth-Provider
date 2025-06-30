package com.ricardo.auth.repository;

import com.ricardo.auth.domain.User;
import org.springframework.stereotype.Repository;

/**
 * Interface de repositório base para a classe User.
 * Se usar outra entidade, deve criar uma interface específica que estenda UserJpaRepository.
 */
@Repository
public interface DefaultUserJpaRepository extends UserJpaRepository<User, Long> {
}