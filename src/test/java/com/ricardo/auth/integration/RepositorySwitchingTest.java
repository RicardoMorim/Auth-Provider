package com.ricardo.auth.integration;

import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.domain.refreshtoken.RefreshToken;
import com.ricardo.auth.domain.user.Email;
import com.ricardo.auth.domain.user.Password;
import com.ricardo.auth.domain.user.User;
import com.ricardo.auth.domain.user.Username;
import com.ricardo.auth.repository.refreshToken.JpaRefreshTokenRepository;
import com.ricardo.auth.repository.refreshToken.PostgreSQLRefreshTokenRepository;
import com.ricardo.auth.repository.refreshToken.RefreshTokenRepository;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for repository switching functionality.
 */
class RepositorySwitchingTest {

    /**
     * The type Jpa repository test.
     */
    @Nested
    @SpringBootTest
    @ActiveProfiles("test")
    @TestPropertySource(properties = {
            "ricardo.auth.repository.type=jpa"
    })
    @Transactional
    class JpaRepositoryTest {

        @Autowired
        private RefreshTokenRepository repository;

        @Autowired
        private PasswordEncoder passwordEncoder;

        @Autowired
        private PasswordPolicyService passwordPolicyService;

        /**
         * Should use jpa repository.
         */
        @Test
        void shouldUseJpaRepository() {
            assertThat(repository).isInstanceOf(JpaRefreshTokenRepository.class);
        }

        /**
         * Should perform basic operations.
         */
        @Test
        void shouldPerformBasicOperations() {
            // Arrange
            User testUser = new User(
                    Username.valueOf("testuser"),
                    Email.valueOf("test@example.com"),
                    Password.valueOf("TestPass@123", passwordEncoder, passwordPolicyService)
            );

            RefreshToken token = new RefreshToken(
                    "jpa-test-token",
                    testUser.getEmail(),
                    Instant.now().plusSeconds(3600)
            );

            // Act
            RefreshToken saved = repository.saveToken(token);
            Optional<RefreshToken> found = repository.findByToken("jpa-test-token");

            // Assert
            assertThat(saved.getId()).isNotNull();
            assertThat(found).isPresent();
            assertThat(found.get().getToken()).isEqualTo("jpa-test-token");
        }
    }

    /**
     * The type Postgre sql repository test.
     */
    @Nested
    @SpringBootTest
    @ActiveProfiles("test")
    @TestPropertySource(properties = {
            "spring.datasource.url=jdbc:postgresql://localhost:5432/AuthLibraryTest",
            "spring.datasource.username=postgres",
            "spring.datasource.password=8080",
            "spring.datasource.driver-class-name=org.postgresql.Driver",
            "ricardo.auth.repository.type=POSTGRESQL",
            // Disable JPA/Hibernate completely when using PostgreSQL
            "spring.jpa.hibernate.ddl-auto=none",
            "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration,org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration"

    })
    @Transactional
    class PostgreSQLRepositoryTest {

        @Autowired
        private RefreshTokenRepository repository;

        @Autowired
        private PasswordEncoder passwordEncoder;

        @Autowired
        private PasswordPolicyService passwordPolicyService;

        /**
         * Should use postgre sql repository.
         */
        @Test
        void shouldUsePostgreSQLRepository() {
            assertThat(repository).isInstanceOf(PostgreSQLRefreshTokenRepository.class);
        }

        /**
         * Should perform basic operations.
         */
        @Test
        void shouldPerformBasicOperations() {
            // Arrange
            User testUser = new User(
                    Username.valueOf("testuser"),
                    Email.valueOf("test@example.com"),
                    Password.valueOf("TestPass@123", passwordEncoder, passwordPolicyService)
            );

            RefreshToken token = new RefreshToken(
                    "postgresql-test-token",
                    testUser.getEmail(),
                    Instant.now().plusSeconds(3600)
            );

            // Act
            RefreshToken saved = repository.saveToken(token);
            Optional<RefreshToken> found = repository.findByToken("postgresql-test-token");

            // Assert
            assertThat(saved.getId()).isNotNull();
            assertThat(found).isPresent();
            assertThat(found.get().getToken()).isEqualTo("postgresql-test-token");
        }
    }
}