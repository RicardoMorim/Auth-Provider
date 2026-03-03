package com.ricardo.auth.service;

import com.ricardo.auth.core.Role;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.domainevents.UserCreatedEvent;
import com.ricardo.auth.domain.domainevents.UserDeletedEvent;
import com.ricardo.auth.domain.domainevents.UserUpdatedEvent;
import com.ricardo.auth.domain.exceptions.DuplicateResourceException;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.helper.CacheHelper;
import com.ricardo.auth.helper.LogSanitizer;
import com.ricardo.auth.repository.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * The type User service.
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 *
 * @param <U>  the type parameter
 * @param <R>  the type parameter
 * @param <ID> the type parameter
 */
public class UserServiceImpl<U extends AuthUser<ID, R>, R extends Role, ID> implements UserService<U, R, ID> {

    private static final Logger log = LoggerFactory.getLogger(UserServiceImpl.class);
    private static final long USER_EXISTS_MIN_PROCESSING_MS = 25L;
    private final UserRepository<U, R, ID> userRepository;
    private final EventPublisher eventPublisher;
    private final CacheHelper<U, R, ID> cacheHelper;

    /**
     * Instantiates a new User service.
     *
     * @param userRepository the user repository
     * @param eventPublisher the event publisher
     * @param cacheHelper    the cache manager
     */
    public UserServiceImpl(UserRepository<U, R, ID> userRepository,
                           EventPublisher eventPublisher,
                           CacheHelper<U, R, ID> cacheHelper) {
        this.userRepository = userRepository;
        this.eventPublisher = eventPublisher;
        this.cacheHelper = cacheHelper;
    }


    @Override
    @Caching(evict = {
            @CacheEvict(value = "userByEmail", allEntries = true),
            @CacheEvict(value = "userByUsername", allEntries = true),
            @CacheEvict(value = "userById", allEntries = true),
            @CacheEvict(value = "users", allEntries = true),
            @CacheEvict(value = "adminCount", allEntries = true),
    })
    public void deleteAllUsers() {
        long startTime = System.currentTimeMillis();
        String operation = "deleteAllUsers";
        log.debug("Starting operation: {}", operation);
        try {
            userRepository.deleteAll();
            log.debug("Operation: {} completed successfully in {}ms", operation, System.currentTimeMillis() - startTime);
        } catch (Exception e) {
            log.error("Operation: {} failed after {}ms. Error: {}", operation, System.currentTimeMillis() - startTime, LogSanitizer.sanitize(e.getMessage()));
            throw e;
        }
    }

    @Override
    @Cacheable(value = "userById", key = "#id", condition = "#id != null")
    public U getUserById(ID id) {
        if (id == null) {
            throw new IllegalArgumentException("Id cannot be null");
        }
        long startTime = System.currentTimeMillis();
        String operation = "getUserById";
        log.debug("Starting operation: {} for id: {}", operation, LogSanitizer.sanitizeId(id));
        try {
            U user = userRepository.findById(id)
                    .orElseThrow(() -> new ResourceNotFoundException("User not found"));
            log.debug("Operation: {} for id: {} completed successfully in {}ms", operation, LogSanitizer.sanitizeId(id), System.currentTimeMillis() - startTime);
            return user;
        } catch (Exception e) {
            log.error("Operation: {} for id: {} failed after {}ms. Error: {}", operation, LogSanitizer.sanitizeId(id), System.currentTimeMillis() - startTime, LogSanitizer.sanitize(e.getMessage()));
            throw e;
        }
    }

    @Override
    @Caching(evict = {
            @CacheEvict(value = "userByEmail", key = "#user.email"),
            @CacheEvict(value = "userByUsername", key = "#user.username"),
            @CacheEvict(value = "userById", key = "#user.id"),
            @CacheEvict(value = "users", allEntries = true),
            @CacheEvict(value = "adminCount", allEntries = true),
    })
    public U createUser(U user) {
        if (user == null) {
            throw new IllegalArgumentException("User cannot be null");
        }
        long startTime = System.currentTimeMillis();
        String operation = "createUser";
        String email = user.getEmail();
        log.debug("Starting operation: {} for email: {}", operation, LogSanitizer.sanitize(email));
        try {
            if (userRepository.existsByEmail(email)) {
                log.warn("Operation: {} failed. Email already exists: {}", operation, LogSanitizer.sanitize(email));
                throw new DuplicateResourceException("Email already exists: " + LogSanitizer.sanitize(email));
            }

            eventPublisher.publishEvent(new UserCreatedEvent(
                    LogSanitizer.sanitize(user.getUsername()),
                    LogSanitizer.sanitize(email),
                    user.getRoles()
            ));
            U savedUser = userRepository.saveUser(user);
            log.debug("Operation: {} for email: {} completed successfully in {}ms", operation, LogSanitizer.sanitize(email), System.currentTimeMillis() - startTime);
            return savedUser;
        } catch (Exception e) {
            log.error("Operation: {} for email: {} failed after {}ms. Error: {}", operation, LogSanitizer.sanitize(email), System.currentTimeMillis() - startTime, LogSanitizer.sanitize(e.getMessage()));
            throw e;
        }
    }

    @Override
    @Caching(evict = {
            @CacheEvict(value = "userById", key = "#id"),
            @CacheEvict(value = "userByEmail", key = "#email"),
            @CacheEvict(value = "userByUsername", key = "#username"),
            @CacheEvict(value = "users", allEntries = true)
    })
    public U updateEmailAndUsername(ID id, String email, String username) {
        long startTime = System.currentTimeMillis();
        String operation = "updateEmailAndUsername";
        log.debug("Starting operation: {} for id: {}", operation, LogSanitizer.sanitizeId(id));
        try {
            U user = getUserById(id);
            if (!user.getEmail().equals(email) &&
                    userRepository.existsByEmail(email)) {
                log.warn("Operation: {} failed for id: {}. Email already exists: {}", operation, LogSanitizer.sanitizeId(id), LogSanitizer.sanitize(email));
                throw new DuplicateResourceException("Email already exists: " + LogSanitizer.sanitize(email));
            }

            user.setUsername(username);
            user.setEmail(email);
            eventPublisher.publishEvent(new UserUpdatedEvent(
                    LogSanitizer.sanitize(username),
                    LogSanitizer.sanitize(email)
            ));
            U updatedUser = userRepository.saveUser(user);
            log.debug("Operation: {} for id: {} completed successfully in {}ms", operation, LogSanitizer.sanitizeId(id), System.currentTimeMillis() - startTime);
            return updatedUser;
        } catch (Exception e) {
            log.error("Operation: {} for id: {} failed after {}ms. Error: {}", operation, LogSanitizer.sanitizeId(id), System.currentTimeMillis() - startTime, LogSanitizer.sanitize(e.getMessage()));
            throw e;
        }
    }

    /**
     * Update the User's information, takes the user Id as the ID, and a User instance with the updated information.
     * IT DOES NOT UPDATE PASSWORD HERE, use `updatePassword` method for that.
     *
     * @param id
     * @param user
     * @return
     */
    @Override
    public U updateUser(ID id, U user) {
        if (id == null) {
            throw new IllegalArgumentException("Id cannot be null");
        }
        long startTime = System.currentTimeMillis();
        String operation = "updateUser";
        log.debug("Starting operation: {} for id: {}", operation, LogSanitizer.sanitizeId(id));
        try {
            U existingUser = getUserById(id);

            if (!existingUser.getEmail().equals(user.getEmail()) &&
                    userRepository.existsByEmail(user.getEmail())) {
                log.warn("Operation: {} failed for id: {}. Email already exists: {}", operation, LogSanitizer.sanitizeId(id), LogSanitizer.sanitize(user.getEmail()));
                throw new DuplicateResourceException("Email already exists: " + LogSanitizer.sanitize(user.getEmail()));
            }

            existingUser.setUsername(user.getUsername());
            existingUser.setEmail(user.getEmail());
            existingUser.setRoles(user.getRoles());

            cacheHelper.evictUserCache(existingUser);
            eventPublisher.publishEvent(new UserUpdatedEvent(
                    LogSanitizer.sanitize(existingUser.getUsername()),
                    LogSanitizer.sanitize(existingUser.getEmail())
            ));
            U savedUser = userRepository.saveUser(existingUser);
            log.debug("Operation: {} for id: {} completed successfully in {}ms", operation, LogSanitizer.sanitizeId(id), System.currentTimeMillis() - startTime);
            return savedUser;
        } catch (Exception e) {
            log.error("Operation: {} for id: {} failed after {}ms. Error: {}", operation, LogSanitizer.sanitizeId(id), System.currentTimeMillis() - startTime, LogSanitizer.sanitize(e.getMessage()));
            throw e;
        }
    }

    @Override
    public U updatePassword(ID id, String encodedPassword) {
        if (id == null) {
            throw new IllegalArgumentException("Id cannot be null");
        }
        long startTime = System.currentTimeMillis();
        String operation = "updatePassword";
        log.debug("Starting operation: {} for id: {}", operation, LogSanitizer.sanitizeId(id));
        try {
            U user = getUserById(id);
            user.setPassword(encodedPassword);
            U savedUser = userRepository.saveUser(user);
            log.debug("Operation: {} for id: {} completed successfully in {}ms", operation, LogSanitizer.sanitizeId(id), System.currentTimeMillis() - startTime);
            return savedUser;
        } catch (Exception e) {
            log.error("Operation: {} for id: {} failed after {}ms. Error: {}", operation, LogSanitizer.sanitizeId(id), System.currentTimeMillis() - startTime, LogSanitizer.sanitize(e.getMessage()));
            throw e;
        }
    }

    @Override
    @Cacheable(value = "userExists", key = "#email", condition = "#email != null")
    public boolean userExists(String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("Email cannot be null or blank");
        }
        long startTime = System.currentTimeMillis();
        String operation = "userExists";
        log.debug("Starting operation: {} for email: {}", operation, LogSanitizer.sanitize(email));
        try {
            boolean exists = userRepository.existsByEmail(email);
            log.debug("Operation: {} for email: {} completed successfully in {}ms", operation, LogSanitizer.sanitize(email), System.currentTimeMillis() - startTime);
            return exists;
        } catch (Exception e) {
            log.error("Operation: {} for email: {} failed after {}ms. Error: {}", operation, LogSanitizer.sanitize(email), System.currentTimeMillis() - startTime, LogSanitizer.sanitize(e.getMessage()));
            throw e;
        } finally {
            ensureMinimumProcessingTime(startTime, USER_EXISTS_MIN_PROCESSING_MS);
        }
    }

    @Override
    @Transactional
    public void deleteUser(ID id) {
        if (id == null) {
            throw new IllegalArgumentException("Id cannot be null");
        }
        long startTime = System.currentTimeMillis();
        String operation = "deleteUser";
        log.debug("Starting operation: {} for id: {}", operation, LogSanitizer.sanitizeId(id));
        try {
            if (!userRepository.existsById(id)) {
                log.warn("Operation: {} failed for id: {}. User not found.", operation, LogSanitizer.sanitizeId(id));
                throw new ResourceNotFoundException("User not found");
            }
            U user = getUserById(id);

            cacheHelper.evictUserCache(user);
            eventPublisher.publishEvent(new UserDeletedEvent(
                    LogSanitizer.sanitize(user.getUsername()),
                    LogSanitizer.sanitize(user.getEmail())
            ));
            userRepository.deleteById(id);
            log.debug("Operation: {} for id: {} completed successfully in {}ms", operation, LogSanitizer.sanitizeId(id), System.currentTimeMillis() - startTime);
        } catch (Exception e) {
            log.error("Operation: {} for id: {} failed after {}ms. Error: {}", operation, LogSanitizer.sanitizeId(id), System.currentTimeMillis() - startTime, LogSanitizer.sanitize(e.getMessage()));
            throw e;
        }
    }

    @Override
    @Transactional
    public void deleteUserByUsername(String username) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username cannot be null or blank");
        }
        U user = userRepository.findByUsername(username).orElse(null);
        if (user == null) {
            throw new ResourceNotFoundException("User not found");
        }
        cacheHelper.evictUserCache(user);
        userRepository.delete(user);
    }

    @Override
    @Cacheable(value = "userByEmail", key = "#email", condition = "#email != null")
    public U getUserByEmail(String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("Email cannot be null or blank");
        }
        long startTime = System.currentTimeMillis();
        String operation = "getUserByEmail";
        log.debug("Starting operation: {} for email: {}", operation, LogSanitizer.sanitize(email));
        try {
            U user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + LogSanitizer.sanitize(email)));

            log.debug("Operation: {} for email: {} completed successfully in {}ms", operation, LogSanitizer.sanitize(email), System.currentTimeMillis() - startTime);
            return user;
        } catch (Exception e) {
            log.error("Operation: {} for email: {} failed after {}ms. Error: {}", operation, LogSanitizer.sanitize(email), System.currentTimeMillis() - startTime, LogSanitizer.sanitize(e.getMessage()));
            throw e;
        }
    }

    private void ensureMinimumProcessingTime(long startTime, long minimumMs) {
        long elapsed = System.currentTimeMillis() - startTime;
        if (elapsed >= minimumMs) {
            return;
        }

        try {
            Thread.sleep(minimumMs - elapsed);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    @Cacheable(value = "users", key = "{#pageable.pageNumber, #pageable.pageSize, #username, #email, #role, #createdAfter, #createdBefore}")
    public List<U> getAllUsers(Pageable pageable, String username, String email,
                               String role, String createdAfter, String createdBefore) {
        long startTime = System.currentTimeMillis();
        String operation = "getAllUsers";
        log.debug("Starting operation: {}", operation);
        try {
            Instant after = createdAfter != null ? Instant.parse(createdAfter) : null;
            Instant before = createdBefore != null ? Instant.parse(createdBefore) : null;
            List<String> roles = role != null ? List.of(role) : null;

            Page<U> users = userRepository.findAllWithFilters(
                    username,
                    email,
                    roles,
                    after,
                    before,
                    pageable
            );
            log.debug("Operation: {} completed successfully in {}ms", operation, System.currentTimeMillis() - startTime);
            return users.getContent();
        } catch (Exception e) {
            log.error("Operation: {} failed after {}ms. Error: {}", operation, System.currentTimeMillis() - startTime, LogSanitizer.sanitize(e.getMessage()));
            throw e;
        }
    }

    @Override
    @Cacheable(value = "allUsersList", key = "{#query, #pageable.pageSize, #pageable.pageNumber}")
    public List<U> searchUsers(String query, Pageable pageable) {
        long startTime = System.currentTimeMillis();
        String operation = "searchUsers";
        log.debug("Starting operation: {} with query: {}", operation, LogSanitizer.sanitize(query));
        try {
            Page<U> users = userRepository.searchByQuery(LogSanitizer.sanitize(query), pageable);
            log.debug("Operation: {} with query: {} completed successfully in {}ms", operation, LogSanitizer.sanitize(query), System.currentTimeMillis() - startTime);
            return users.getContent();
        } catch (Exception e) {
            log.error("Operation: {} with query: {} failed after {}ms. Error: {}", operation, LogSanitizer.sanitize(query), System.currentTimeMillis() - startTime, LogSanitizer.sanitize(e.getMessage()));
            throw e;
        }
    }

    @Override
    public Optional<U> authenticate(String email, String rawPassword, PasswordEncoder encoder) {
        long startTime = System.currentTimeMillis();
        String operation = "authenticate";
        log.debug("Starting operation: {} for email: {}", operation, LogSanitizer.sanitize(email));
        try {
            Optional<U> userOpt = userRepository.findByEmail(email)
                    .filter(user -> encoder.matches(rawPassword, user.getPassword()));
            log.debug("Operation: {} for email: {} completed in {}ms. User found: {}", operation, LogSanitizer.sanitize(email), System.currentTimeMillis() - startTime, userOpt.isPresent());
            return userOpt;
        } catch (Exception e) {
            log.error("Operation: {} for email: {} failed after {}ms. Error: {}", operation, LogSanitizer.sanitize(email), System.currentTimeMillis() - startTime, LogSanitizer.sanitize(e.getMessage()));
            throw e;
        }
    }

    @Override
    @Cacheable(value = "userByUsername", key = "#username", condition = "#username != null")
    public U getUserByUserName(String username) {
        long startTime = System.currentTimeMillis();
        String operation = "getUserByUserName";
        log.debug("Starting operation: {} for username: {}", operation, LogSanitizer.sanitize(username));
        try {
            U user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new ResourceNotFoundException("User not found with username: " + LogSanitizer.sanitize(username)));
            log.debug("Operation: {} for username: {} completed successfully in {}ms", operation, LogSanitizer.sanitize(username), System.currentTimeMillis() - startTime);
            return user;
        } catch (Exception e) {
            log.error("Operation: {} for username: {} failed after {}ms. Error: {}", operation, LogSanitizer.sanitize(username), System.currentTimeMillis() - startTime, LogSanitizer.sanitize(e.getMessage()));
            throw e;
        }
    }

    @Override
    @Cacheable(value = "adminCount")
    public int countAdmins() {
        long startTime = System.currentTimeMillis();
        String operation = "countAdmins";
        log.debug("Starting operation: {}", operation);
        try {
            int count = userRepository.countUsersByRole("ADMIN");
            log.debug("Operation: {} completed successfully in {}ms", operation, System.currentTimeMillis() - startTime);
            return count;
        } catch (Exception e) {
            log.error("Operation: {} failed after {}ms. Error: {}", operation, System.currentTimeMillis() - startTime, LogSanitizer.sanitize(e.getMessage()));
            throw e;
        }
    }
}


