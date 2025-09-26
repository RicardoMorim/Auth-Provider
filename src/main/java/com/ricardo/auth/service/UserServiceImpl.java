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

    // --- LOG SANITIZATION HELPER ---
    private static String sanitizeForLogging(String input) {
        if (input == null) {
            return "null";
        }
        return input
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
                .replace("\"", "\\\"")
                .trim();
    }

    private static String sanitizeIdForLogging(Object id) {
        if (id == null) return "null";
        return sanitizeForLogging(id.toString());
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
            log.info("Operation: {} completed successfully in {}ms", operation, System.currentTimeMillis() - startTime);
        } catch (Exception e) {
            log.error("Operation: {} failed after {}ms. Error: {}", operation, System.currentTimeMillis() - startTime, sanitizeForLogging(e.getMessage()));
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
        log.debug("Starting operation: {} for id: {}", operation, sanitizeIdForLogging(id));
        try {
            U user = userRepository.findById(id)
                    .orElseThrow(() -> new ResourceNotFoundException("User not found"));
            log.info("Operation: {} for id: {} completed successfully in {}ms", operation, sanitizeIdForLogging(id), System.currentTimeMillis() - startTime);
            return user;
        } catch (Exception e) {
            log.error("Operation: {} for id: {} failed after {}ms. Error: {}", operation, sanitizeIdForLogging(id), System.currentTimeMillis() - startTime, sanitizeForLogging(e.getMessage()));
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
        log.debug("Starting operation: {} for email: {}", operation, sanitizeForLogging(email));
        try {
            if (userRepository.existsByEmail(email)) {
                log.warn("Operation: {} failed. Email already exists: {}", operation, sanitizeForLogging(email));
                throw new DuplicateResourceException("Email already exists: " + sanitizeForLogging(email));
            }

            eventPublisher.publishEvent(new UserCreatedEvent(
                    sanitizeForLogging(user.getUsername()),
                    sanitizeForLogging(email),
                    user.getRoles()
            ));
            U savedUser = userRepository.saveUser(user);
            log.info("Operation: {} for email: {} completed successfully in {}ms", operation, sanitizeForLogging(email), System.currentTimeMillis() - startTime);
            return savedUser;
        } catch (Exception e) {
            log.error("Operation: {} for email: {} failed after {}ms. Error: {}", operation, sanitizeForLogging(email), System.currentTimeMillis() - startTime, sanitizeForLogging(e.getMessage()));
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
        log.debug("Starting operation: {} for id: {}", operation, sanitizeIdForLogging(id));
        try {
            U user = getUserById(id);
            if (!user.getEmail().equals(email) &&
                    userRepository.existsByEmail(email)) {
                log.warn("Operation: {} failed for id: {}. Email already exists: {}", operation, sanitizeIdForLogging(id), sanitizeForLogging(email));
                throw new DuplicateResourceException("Email already exists: " + sanitizeForLogging(email));
            }

            user.setUsername(username);
            user.setEmail(email);
            eventPublisher.publishEvent(new UserUpdatedEvent(
                    sanitizeForLogging(username),
                    sanitizeForLogging(email)
            ));
            U updatedUser = userRepository.saveUser(user);
            log.info("Operation: {} for id: {} completed successfully in {}ms", operation, sanitizeIdForLogging(id), System.currentTimeMillis() - startTime);
            return updatedUser;
        } catch (Exception e) {
            log.error("Operation: {} for id: {} failed after {}ms. Error: {}", operation, sanitizeIdForLogging(id), System.currentTimeMillis() - startTime, sanitizeForLogging(e.getMessage()));
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
        log.debug("Starting operation: {} for id: {}", operation, sanitizeIdForLogging(id));
        try {
            U existingUser = getUserById(id);

            if (!existingUser.getEmail().equals(user.getEmail()) &&
                    userRepository.existsByEmail(user.getEmail())) {
                log.warn("Operation: {} failed for id: {}. Email already exists: {}", operation, sanitizeIdForLogging(id), sanitizeForLogging(user.getEmail()));
                throw new DuplicateResourceException("Email already exists: " + sanitizeForLogging(user.getEmail()));
            }

            existingUser.setUsername(user.getUsername());
            existingUser.setEmail(user.getEmail());
            existingUser.setRoles(user.getRoles());

            cacheHelper.evictUserCache(existingUser);
            eventPublisher.publishEvent(new UserUpdatedEvent(
                    sanitizeForLogging(existingUser.getUsername()),
                    sanitizeForLogging(existingUser.getEmail())
            ));
            U savedUser = userRepository.saveUser(existingUser);
            log.info("Operation: {} for id: {} completed successfully in {}ms", operation, sanitizeIdForLogging(id), System.currentTimeMillis() - startTime);
            return savedUser;
        } catch (Exception e) {
            log.error("Operation: {} for id: {} failed after {}ms. Error: {}", operation, sanitizeIdForLogging(id), System.currentTimeMillis() - startTime, sanitizeForLogging(e.getMessage()));
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
        log.debug("Starting operation: {} for id: {}", operation, sanitizeIdForLogging(id));
        try {
            U user = getUserById(id);
            user.setPassword(encodedPassword);
            U savedUser = userRepository.saveUser(user);
            log.info("Operation: {} for id: {} completed successfully in {}ms", operation, sanitizeIdForLogging(id), System.currentTimeMillis() - startTime);
            return savedUser;
        } catch (Exception e) {
            log.error("Operation: {} for id: {} failed after {}ms. Error: {}", operation, sanitizeIdForLogging(id), System.currentTimeMillis() - startTime, sanitizeForLogging(e.getMessage()));
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
        log.debug("Starting operation: {} for email: {}", operation, sanitizeForLogging(email));
        try {
            boolean exists = userRepository.existsByEmail(email);
            log.info("Operation: {} for email: {} completed successfully in {}ms", operation, sanitizeForLogging(email), System.currentTimeMillis() - startTime);
            return exists;
        } catch (Exception e) {
            log.error("Operation: {} for email: {} failed after {}ms. Error: {}", operation, sanitizeForLogging(email), System.currentTimeMillis() - startTime, sanitizeForLogging(e.getMessage()));
            throw e;
        }
    }

    @Override
    public void deleteUser(ID id) {
        if (id == null) {
            throw new IllegalArgumentException("Id cannot be null");
        }
        long startTime = System.currentTimeMillis();
        String operation = "deleteUser";
        log.debug("Starting operation: {} for id: {}", operation, sanitizeIdForLogging(id));
        try {
            if (!userRepository.existsById(id)) {
                log.warn("Operation: {} failed for id: {}. User not found.", operation, sanitizeIdForLogging(id));
                throw new ResourceNotFoundException("User not found");
            }
            U user = getUserById(id);

            cacheHelper.evictUserCache(user);
            eventPublisher.publishEvent(new UserDeletedEvent(
                    sanitizeForLogging(user.getUsername()),
                    sanitizeForLogging(user.getEmail())
            ));
            userRepository.deleteById(id);
            log.info("Operation: {} for id: {} completed successfully in {}ms", operation, sanitizeIdForLogging(id), System.currentTimeMillis() - startTime);
        } catch (Exception e) {
            log.error("Operation: {} for id: {} failed after {}ms. Error: {}", operation, sanitizeIdForLogging(id), System.currentTimeMillis() - startTime, sanitizeForLogging(e.getMessage()));
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
        log.debug("Starting operation: {} for email: {}", operation, sanitizeForLogging(email));
        try {
            U user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + sanitizeForLogging(email)));

            log.info("Operation: {} for email: {} completed successfully in {}ms", operation, sanitizeForLogging(email), System.currentTimeMillis() - startTime);
            return user;
        } catch (Exception e) {
            log.error("Operation: {} for email: {} failed after {}ms. Error: {}", operation, sanitizeForLogging(email), System.currentTimeMillis() - startTime, sanitizeForLogging(e.getMessage()));
            throw e;
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
            log.info("Operation: {} completed successfully in {}ms", operation, System.currentTimeMillis() - startTime);
            return users.getContent();
        } catch (Exception e) {
            log.error("Operation: {} failed after {}ms. Error: {}", operation, System.currentTimeMillis() - startTime, sanitizeForLogging(e.getMessage()));
            throw e;
        }
    }

    @Override
    @Cacheable(value = "allUsersList", key = "{#query, #pageable.pageSize, #pageable.pageNumber}")
    public List<U> searchUsers(String query, Pageable pageable) {
        long startTime = System.currentTimeMillis();
        String operation = "searchUsers";
        log.debug("Starting operation: {} with query: {}", operation, sanitizeForLogging(query));
        try {
            Page<U> users = userRepository.searchByQuery(sanitizeForLogging(query), pageable);
            log.info("Operation: {} with query: {} completed successfully in {}ms", operation, sanitizeForLogging(query), System.currentTimeMillis() - startTime);
            return users.getContent();
        } catch (Exception e) {
            log.error("Operation: {} with query: {} failed after {}ms. Error: {}", operation, sanitizeForLogging(query), System.currentTimeMillis() - startTime, sanitizeForLogging(e.getMessage()));
            throw e;
        }
    }

    @Override
    public Optional<U> authenticate(String email, String rawPassword, PasswordEncoder encoder) {
        long startTime = System.currentTimeMillis();
        String operation = "authenticate";
        log.debug("Starting operation: {} for email: {}", operation, sanitizeForLogging(email));
        try {
            Optional<U> userOpt = userRepository.findByEmail(email)
                    .filter(user -> encoder.matches(rawPassword, user.getPassword()));
            log.info("Operation: {} for email: {} completed in {}ms. User found: {}", operation, sanitizeForLogging(email), System.currentTimeMillis() - startTime, userOpt.isPresent());
            return userOpt;
        } catch (Exception e) {
            log.error("Operation: {} for email: {} failed after {}ms. Error: {}", operation, sanitizeForLogging(email), System.currentTimeMillis() - startTime, sanitizeForLogging(e.getMessage()));
            throw e;
        }
    }

    @Override
    @Cacheable(value = "userByUsername", key = "#username", condition = "#username != null")
    public U getUserByUserName(String username) {
        long startTime = System.currentTimeMillis();
        String operation = "getUserByUserName";
        log.debug("Starting operation: {} for username: {}", operation, sanitizeForLogging(username));
        try {
            U user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new ResourceNotFoundException("User not found with username: " + sanitizeForLogging(username)));
            log.info("Operation: {} for username: {} completed successfully in {}ms", operation, sanitizeForLogging(username), System.currentTimeMillis() - startTime);
            return user;
        } catch (Exception e) {
            log.error("Operation: {} for username: {} failed after {}ms. Error: {}", operation, sanitizeForLogging(username), System.currentTimeMillis() - startTime, sanitizeForLogging(e.getMessage()));
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
            log.info("Operation: {} completed successfully in {}ms", operation, System.currentTimeMillis() - startTime);
            return count;
        } catch (Exception e) {
            log.error("Operation: {} failed after {}ms. Error: {}", operation, System.currentTimeMillis() - startTime, sanitizeForLogging(e.getMessage()));
            throw e;
        }
    }
}