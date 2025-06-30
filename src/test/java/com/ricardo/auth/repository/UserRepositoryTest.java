package com.ricardo.auth.repository;

import com.ricardo.auth.domain.Email;
import com.ricardo.auth.domain.Password;
import com.ricardo.auth.domain.User;
import com.ricardo.auth.domain.Username;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The type User repository test.
 */
@DataJpaTest
@ActiveProfiles("test")
public class UserRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private DefaultUserJpaRepository userRepository;

    /**
     * Sets up.
     */
    @BeforeEach
    void setUp() {
        Username username = Username.valueOf("testuser");
        Email email = Email.valueOf("test@example.com");
        Password password = Password.fromHash(new BCryptPasswordEncoder().encode("password123"));
        User user = new User(username, email, password);
        entityManager.persist(user);
        entityManager.flush();
    }

    /**
     * Find by email should return user when email exists.
     */
    @Test
    void findByEmail_shouldReturnUser_whenEmailExists() {
        // Act
        Optional<User> foundUser = userRepository.findByEmail("test@example.com");

        // Assert
        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().getEmail()).isEqualTo("test@example.com");
    }

    /**
     * Find by email should return empty when email does not exist.
     */
    @Test
    void findByEmail_shouldReturnEmpty_whenEmailDoesNotExist() {
        // Act
        Optional<User> foundUser = userRepository.findByEmail("nonexistent@example.com");

        // Assert
        assertThat(foundUser).isNotPresent();
    }

    /**
     * Exists by email should return true when email exists.
     */
    @Test
    void existsByEmail_shouldReturnTrue_whenEmailExists() {
        // Act
        boolean exists = userRepository.existsByEmail("test@example.com");

        // Assert
        assertThat(exists).isTrue();
    }

    /**
     * Exists by email should return false when email does not exist.
     */
    @Test
    void existsByEmail_shouldReturnFalse_whenEmailDoesNotExist() {
        // Act
        boolean exists = userRepository.existsByEmail("nonexistent@example.com");

        // Assert
        assertThat(exists).isFalse();
    }
}