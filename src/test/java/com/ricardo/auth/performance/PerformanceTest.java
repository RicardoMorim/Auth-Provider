package com.ricardo.auth.performance;

import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.user.*;
import com.ricardo.auth.repository.user.DefaultUserJpaRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Performance and concurrency tests for authentication components.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PerformanceTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserService<User, AppRole, UUID> userService;

    @Autowired
    private DefaultUserJpaRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private PasswordPolicyService passwordPolicyService;

    @Autowired
    private PlatformTransactionManager transactionManager;

    /**
     * Sets up.
     */
    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    /**
     * Tear down.
     */
    @AfterEach
    void tearDown() {
        // Additional cleanup
        userRepository.deleteAll();
        SecurityContextHolder.clearContext();
    }

    /**
     * Should handle high volume token generation.
     */
    @Test
    void shouldHandleHighVolumeTokenGeneration() {
        // Arrange
        int tokenCount = 1000;
        String userEmail = "test@example.com";
        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));

        // Act
        Instant start = Instant.now();

        List<String> tokens = IntStream.range(0, tokenCount)
                .parallel()
                .mapToObj(i -> jwtService.generateAccessToken(userEmail, authorities))
                .toList();

        Instant end = Instant.now();
        Duration duration = Duration.between(start, end);

        // Assert
        assertThat(tokens).hasSize(tokenCount);
        assertThat(tokens.stream().distinct().count()).isEqualTo(tokenCount); // All unique
        assertThat(duration.toMillis()).isLessThan(5000); // Should complete within 5 seconds
    }

    /**
     * Should handle concurrent user creation.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldHandleConcurrentUserCreation() throws Exception {
        // Arrange
        int userCount = 50;
        ExecutorService executor = Executors.newFixedThreadPool(10);

        // Act
        List<CompletableFuture<User>> futures = IntStream.range(0, userCount)
                .mapToObj(i -> CompletableFuture.supplyAsync(() -> {
                    try {
                        return userService.createUser(
                                new User(
                                        Username.valueOf("user" + i),
                                        Email.valueOf("user" + i + "@example.com"),
                                        Password.valueOf("TestPass@123", passwordEncoder, passwordPolicyService)
                                )
                        );
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, executor))
                .toList();

        // Wait for all to complete
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        // Assert
        List<User> users = futures.stream()
                .map(CompletableFuture::join)
                .toList();

        assertThat(users).hasSize(userCount);
        assertThat(userRepository.count()).isEqualTo(userCount);

        // Verify all users are unique
        long uniqueEmails = users.stream()
                .map(User::getEmail)
                .distinct()
                .count();
        assertThat(uniqueEmails).isEqualTo(userCount);

        executor.shutdown();
    }

    /**
     * Should handle high volume token validation.
     */
    @Test
    void shouldHandleHighVolumeTokenValidation() {
        // Arrange
        String userEmail = "test@example.com";
        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        String token = jwtService.generateAccessToken(userEmail, authorities);
        int validationCount = 1000;

        // Act
        Instant start = Instant.now();

        List<Boolean> results = IntStream.range(0, validationCount)
                .parallel()
                .mapToObj(i -> jwtService.isTokenValid(token))
                .toList();

        Instant end = Instant.now();
        Duration duration = Duration.between(start, end);

        // Assert
        assertThat(results).hasSize(validationCount);
        assertThat(results.stream().allMatch(result -> result)).isTrue();
        assertThat(duration.toMillis()).isLessThan(3000); // Should complete within 3 seconds
    }

    /**
     * Should handle concurrent user lookup.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    @DirtiesContext(methodMode = DirtiesContext.MethodMode.AFTER_METHOD)
    @Transactional
    @DisplayName("Should handle concurrent user lookup efficiently")
    void shouldHandleConcurrentUserLookup() throws InterruptedException {
        // Step 1: Create users in separate committed transaction
        List<User> testUsers = createUsersInSeparateTransaction();

        // Step 2: Wait a bit to ensure transaction is fully committed
        Thread.sleep(100);

        // Step 3: Run concurrent test with proper synchronization
        runConcurrentLookupTest(testUsers);
    }

    private List<User> createUsersInSeparateTransaction() {
        TransactionTemplate transactionTemplate = new TransactionTemplate(transactionManager);
        transactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);

        return transactionTemplate.execute(status -> {
            // Clear existing data
            userRepository.deleteAll();
            userRepository.flush(); // Force delete to complete

            // Create 100 test users
            List<User> users = new ArrayList<>();
            for (int i = 0; i < 100; i++) {
                User user = new User(
                        Username.valueOf("testuser" + i),
                        Email.valueOf("test" + i + "@example.com"),
                        Password.valueOf("Password@123", passwordEncoder, passwordPolicyService)
                );
                user.addRole(AppRole.USER);
                users.add(userRepository.save(user));
            }

            // Flush to ensure data is written
            userRepository.flush();

            System.out.println("✅ Created " + users.size() + " users in committed transaction");
            return users;
        });
    }

    private void runConcurrentLookupTest(List<User> testUsers) throws InterruptedException {
        // Verify users exist in current transaction context
        for (int i = 0; i < testUsers.size(); i++) {
            String email = "test" + i + "@example.com";
            // Use a fresh query that doesn't involve the entities from the previous transaction
            boolean exists = userRepository.findByEmail_Email(email).isPresent();
            assertTrue(exists, "User with email " + email + " should exist");
        }

        // Create synchronization tools
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(100);

        // Record start time
        long startTime = System.currentTimeMillis();

        // Create concurrent lookup tasks
        List<CompletableFuture<User>> futures = IntStream.range(0, 100)
                .mapToObj(i -> CompletableFuture.supplyAsync(() -> {
                    try {
                        // Wait for all threads to be ready
                        startLatch.await();

                        // Look up user
                        String email = "test" + i + "@example.com";
                        return userService.getUserByEmail(email);
                    } catch (Exception e) {
                        throw new RuntimeException("Failed to lookup user test" + i + "@example.com: " + e.getMessage(), e);
                    } finally {
                        doneLatch.countDown();
                    }
                }))
                .collect(Collectors.toList());

        // Start all threads simultaneously
        startLatch.countDown();

        // Wait for completion
        boolean completed = doneLatch.await(10, TimeUnit.SECONDS);
        assertTrue(completed, "All operations should complete within 10 seconds");

        long endTime = System.currentTimeMillis();

        // Collect results
        List<User> results = futures.stream()
                .map(future -> {
                    try {
                        return future.get(1, TimeUnit.SECONDS);
                    } catch (Exception e) {
                        throw new RuntimeException("Future failed: " + e.getMessage(), e);
                    }
                })
                .collect(Collectors.toList());

        // Verify results
        assertThat(results).hasSize(100);
        assertThat(endTime - startTime).isLessThan(5000);

        // Verify we got the correct users
        for (int i = 0; i < 100; i++) {
            User user = results.get(i);
            assertNotNull(user);
            assertEquals("test" + i + "@example.com", user.getEmail());
            assertEquals("testuser" + i, user.getUsername());
        }

        System.out.println("✅ Concurrent lookup completed in " + (endTime - startTime) + "ms");
    }

    /**
     * Should handle password hashing performance.
     */
    @Test
    void shouldHandlePasswordHashingPerformance() {
        // Arrange
        int hashCount = 50;
        String password = "TestPassword@123";

        // Act
        Instant start = Instant.now();

        List<String> hashes = IntStream.range(0, hashCount)
                .parallel()
                .mapToObj(i -> passwordEncoder.encode(password))
                .toList();

        Instant end = Instant.now();
        Duration duration = Duration.between(start, end);

        // Assert
        assertThat(hashes).hasSize(hashCount);
        assertThat(hashes.stream().distinct().count()).isEqualTo(hashCount); // All unique
        assertThat(duration.toMillis()).isLessThan(10000); // Should complete within 10 seconds

        // Verify all hashes are valid
        assertThat(hashes.stream().allMatch(hash -> passwordEncoder.matches(password, hash))).isTrue();
    }
}