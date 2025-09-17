package com.ricardo.auth.service;

import com.ricardo.auth.core.Role;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.domainevents.UserCreatedEvent;
import com.ricardo.auth.domain.domainevents.UserDeletedEvent;
import com.ricardo.auth.domain.domainevents.UserUpdatedEvent;
import com.ricardo.auth.domain.exceptions.DuplicateResourceException;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import com.ricardo.auth.domain.user.AuthUser;
import com.ricardo.auth.repository.user.UserRepository;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;

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

    private final UserRepository<U, R, ID> userRepository;
    private final EventPublisher eventPublisher;
    private final CacheManager cacheManager;
    private final UserMetricsService userMetricsService;

    /**
     * Instantiates a new User service.
     *
     * @param userRepository     the user repository
     * @param eventPublisher     the event publisher
     * @param cacheManager       the cache manager
     * @param userMetricsService the service to record database operation metrics
     */
    public UserServiceImpl(UserRepository<U, R, ID> userRepository,
                           EventPublisher eventPublisher,
                           CacheManager cacheManager,
                           UserMetricsService userMetricsService) { // Add dependency
        this.userRepository = userRepository;
        this.eventPublisher = eventPublisher;
        this.cacheManager = cacheManager;
        this.userMetricsService = userMetricsService; // Assign dependency
    }

    @Override
    @Cacheable(value = "userById", key = "#id")
    public U getUserById(ID id) {
        long startTime = System.currentTimeMillis();
        String operation = "getUserById";
        try {
            U user = userRepository.findById(id)
                    .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), true);
            return user;
        } catch (Exception e) {
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), false);
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
    }, put = {
            @CachePut(value = "userByEmail", key = "#user.email"),
            @CachePut(value = "userByUsername", key = "#user.username"),
            @CachePut(value = "userById", key = "#user.id"),
    })
    public U createUser(U user) {
        long startTime = System.currentTimeMillis();
        String operation = "createUser";
        try {
            if (userRepository.existsByEmail(user.getEmail())) {
                userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), false);
                throw new DuplicateResourceException("Email already exists: " + user.getEmail());
            }

            eventPublisher.publishEvent(new UserCreatedEvent(user.getUsername(), user.getEmail(), user.getRoles()));
            U savedUser = userRepository.saveUser(user); // Record time after save
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), true);
            return savedUser;
        } catch (Exception e) {
            // Only record if not already recorded due to DuplicateResourceException
            if (!(e instanceof DuplicateResourceException)) {
                userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), false);
            }
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
        try {
            U user = getUserById(id); // This might have its own metric recorded

            // Validate email uniqueness if changing email
            if (!user.getEmail().equals(email) &&
                    userRepository.existsByEmail(email)) {
                userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), false);
                throw new DuplicateResourceException("Email already exists: " + email);
            }

            user.setUsername(username);
            user.setEmail(email);
            eventPublisher.publishEvent(new UserUpdatedEvent(user.getUsername(), user.getEmail()));
            U updatedUser = userRepository.saveUser(user); // Record time after save
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), true);
            return updatedUser;
        } catch (Exception e) {
            // Only record if not already recorded due to DuplicateResourceException
            if (!(e instanceof DuplicateResourceException)) {
                userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), false);
            }
            throw e;
        }
    }

    @Override
    @CachePut(value = "userById", key = "#id")
    @CacheEvict(value = "users", allEntries = true)
    public U updateUser(ID id, U user) {
        long startTime = System.currentTimeMillis();
        String operation = "updateUser";
        try {
            U existingUser = getUserById(id); // This might have its own metric recorded

            // Validate email uniqueness if changing email
            if (!existingUser.getEmail().equals(user.getEmail()) &&
                    userRepository.existsByEmail(user.getEmail())) {
                userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), false);
                throw new DuplicateResourceException("Email already exists: " + user.getEmail());
            }

            existingUser.setUsername(user.getUsername());
            existingUser.setEmail(user.getEmail());
            existingUser.setRoles(user.getRoles());
            // PASSWORD IS NOT UPDATED HERE IT HAS ITS OWN METHOD `updatePassword`

            eventPublisher.publishEvent(new UserUpdatedEvent(existingUser.getUsername(), existingUser.getEmail()));
            U savedUser = userRepository.saveUser(existingUser); // Record time after save
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), true);
            return savedUser;
        } catch (Exception e) {
            // Only record if not already recorded due to DuplicateResourceException
            if (!(e instanceof DuplicateResourceException)) {
                userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), false);
            }
            throw e;
        }
    }

    @Override
    public U updatePassword(ID id, String encodedPassword) {
        long startTime = System.currentTimeMillis();
        String operation = "updatePassword";
        try {
            U user = getUserById(id); // This might have its own metric recorded

            user.setPassword(encodedPassword);
            U savedUser = userRepository.saveUser(user); // Record time after save
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), true);
            return savedUser;
        } catch (Exception e) {
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), false);
            throw e;
        }
    }

    @Override
    @Cacheable(value = "userExists", key = "#email")
    public boolean userExists(String email) {
        long startTime = System.currentTimeMillis();
        String operation = "userExists";
        try {
            boolean exists = userRepository.existsByEmail(email);
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), true);
            return exists;
        } catch (Exception e) {
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), false);
            throw e;
        }
    }

    @Override
    public void deleteUser(ID id) {
        long startTime = System.currentTimeMillis();
        String operation = "deleteUser";
        try {
            if (!userRepository.existsById(id)) {
                userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), false);
                throw new ResourceNotFoundException("User not found with id: " + id);
            }
            U user = getUserById(id); // This might have its own metric recorded

            evictCache("userById", id);
            evictCache("userByEmail", user.getEmail());
            evictCache("userByUsername", user.getUsername());
            evictCache("userExists", user.getEmail());
            clearCache("users");
            clearCache("adminCount");

            eventPublisher.publishEvent(new UserDeletedEvent(user.getUsername(), user.getEmail()));
            userRepository.deleteById(id); // Record time after deletion
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), true);
        } catch (Exception e) {
            // Only record if not already recorded due to ResourceNotFoundException
            if (!(e instanceof ResourceNotFoundException)) {
                userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), false);
            }
            throw e;
        }
    }

    @Override
    @Cacheable(value = "userByEmail", key = "#email")
    public U getUserByEmail(String email) {
        long startTime = System.currentTimeMillis();
        String operation = "getUserByEmail";
        try {
            U user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), true);
            return user;
        } catch (Exception e) {
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), false);
            throw e;
        }
    }

    @Override
    @Cacheable(value = "users", key = "{#pageable.pageNumber, #pageable.pageSize, #username, #email, #role, #createdAfter, #createdBefore}")
    public List<U> getAllUsers(Pageable pageable, String username, String email,
                               String role, String createdAfter, String createdBefore) {
        long startTime = System.currentTimeMillis();
        String operation = "getAllUsers";
        try {
            // Parse dates safely if needed, or handle potential parse exceptions
            Instant after = createdAfter != null ? Instant.parse(createdAfter) : null;
            Instant before = createdBefore != null ? Instant.parse(createdBefore) : null;
            List<String> roles = role != null ? List.of(role) : List.of();

            Page<U> users = userRepository.findAllWithFilters(username, email, roles, after, before, pageable);
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), true);
            return users.getContent();
        } catch (Exception e) {
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), false);
            throw e; // Re-throw to maintain original behavior
        }
    }

    @Override
    @Cacheable(value = "allUsersList", key = "{#query, #pageable.pageSize, #pageable.pageNumber}")
    public List<U> searchUsers(String query, Pageable pageable) {
        long startTime = System.currentTimeMillis();
        String operation = "searchUsers";
        try {
            Page<U> users = userRepository.searchByQuery(query, pageable);
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), true);
            return users.getContent();
        } catch (Exception e) {
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), false);
            throw e; // Re-throw to maintain original behavior
        }
    }

    @Override
    public Optional<U> authenticate(String email, String rawPassword, PasswordEncoder encoder) {
        long startTime = System.currentTimeMillis();
        String operation = "authenticate";
        try {
            Optional<U> userOpt = userRepository.findByEmail(email)
                    .filter(user -> encoder.matches(rawPassword, user.getPassword()));
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), userOpt.isPresent());
            return userOpt;
        } catch (Exception e) {
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), false);
            throw e;
        }
    }

    @Override
    @Cacheable(value = "userByUsername", key = "#username")
    public U getUserByUserName(String username) {
        long startTime = System.currentTimeMillis();
        String operation = "getUserByUserName";
        try {
            U user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new ResourceNotFoundException("User not found with username: " + username));
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), true);
            return user;
        } catch (Exception e) {
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), false);
            throw e;
        }
    }

    @Override
    @Cacheable(value = "adminCount")
    public int countAdmins() {
        long startTime = System.currentTimeMillis();
        String operation = "countAdmins";
        try {
            int count = userRepository.countUsersByRole("ADMIN");
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), true);
            return count;
        } catch (Exception e) {
            userMetricsService.recordOperation(operation, startTime, System.currentTimeMillis(), false);
            throw e;
        }
    }

    // Helper methods remain unchanged
    private void evictCache(String cacheName, Object key) {
        Cache cache = cacheManager.getCache(cacheName);
        if (cache != null) {
            cache.evict(key);
        }
    }

    private void clearCache(String cacheName) {
        Cache cache = cacheManager.getCache(cacheName);
        if (cache != null) {
            cache.clear();
        }
    }
}