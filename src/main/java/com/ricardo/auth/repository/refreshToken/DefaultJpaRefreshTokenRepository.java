package com.ricardo.auth.repository.refreshToken;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Repository;

/**
 * Default JPA implementation for RefreshTokenRepository.
 * This will be used when JPA repository type is configured.
 * If you want to use a custom repository implementation, create a class that implements JpaRefreshTokenRepository and annotate it with @Repository.
 * If you want to use the postgreSQL implementation, change the property `ricardo.auth.refresh-tokens.repository.type` to `postgresql`.
 */
@Repository
@ConditionalOnMissingBean(RefreshTokenRepository.class)
@ConditionalOnProperty(prefix = "ricardo.auth.refresh-tokens.repository", name = "type", havingValue = "jpa", matchIfMissing = true)
public interface DefaultJpaRefreshTokenRepository extends JpaRefreshTokenRepository {
    // No additional methods needed - inherits everything from JpaRefreshTokenRepository
}