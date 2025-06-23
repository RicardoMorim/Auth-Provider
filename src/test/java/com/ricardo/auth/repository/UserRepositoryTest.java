package com.ricardo.auth.repository;

import com.ricardo.auth.domain.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@ActiveProfiles("test")
public class UserRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private UserJpaRepository userRepository; // Use the concrete implementation

    @BeforeEach
    void setUp() {
        Username username = Username.valueOf("testuser");
        Email email = Email.valueOf("test@example.com");
        Password password = Password.fromHash(new BCryptPasswordEncoder().encode("password123"));
        User user = new User(username, email, password);
        entityManager.persist(user);
        entityManager.flush();
    }

    @Test
    void findByEmail_shouldReturnUser_whenEmailExists() {
        // Act
        Optional<User> foundUser = userRepository.findByEmail("test@example.com");

        // Assert
        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().getEmail()).isEqualTo("test@example.com");
    }

    @Test
    void findByEmail_shouldReturnEmpty_whenEmailDoesNotExist() {
        // Act
        Optional<User> foundUser = userRepository.findByEmail("nonexistent@example.com");

        // Assert
        assertThat(foundUser).isNotPresent();
    }

    @Test
    void existsByEmail_shouldReturnTrue_whenEmailExists() {
        // Act
        boolean exists = userRepository.existsByEmail("test@example.com");

        // Assert
        assertThat(exists).isTrue();
    }

    @Test
    void existsByEmail_shouldReturnFalse_whenEmailDoesNotExist() {
        // Act
        boolean exists = userRepository.existsByEmail("nonexistent@example.com");

        // Assert
        assertThat(exists).isFalse();
    }
}