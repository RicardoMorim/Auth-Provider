package com.ricardo.auth.repository.user;

import com.ricardo.auth.domain.user.User;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Repository;

/**
 * Interface de repositório base para a classe User.
 * If you want to use a custom repository implementation, create a class that implements UserJpaRepository and annotate it with @Repository.
 * This repository will be used by default if no other implementation is provided.
 * This interface is marked with @ConditionalOnMissingBean to ensure that it is only used when no other UserJpaRepository bean is defined in the application context.
 */
@Repository
@ConditionalOnMissingBean(name = "userRepository")
public interface DefaultUserJpaRepository extends UserJpaRepository<User, Long> {
    // No additional methods needed - inherits everything from UserJpaRepository
}