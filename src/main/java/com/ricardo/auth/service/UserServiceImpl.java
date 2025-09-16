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


    /**
     * Instantiates a new User service.
     *
     * @param userRepository the user repository
     * @param eventPublisher the event publisher
     */
    public UserServiceImpl(UserRepository<U, R, ID> userRepository, EventPublisher eventPublisher, CacheManager cacheManager) {
        this.eventPublisher = eventPublisher;
        this.userRepository = userRepository;
        this.cacheManager = cacheManager;
    }

    @Override
    @Cacheable(value = "userById", key = "#id")
    public U getUserById(ID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));
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
        if (userRepository.existsByEmail(user.getEmail())) {
            throw new DuplicateResourceException("Email already exists: " + user.getEmail());
        }

        eventPublisher.publishEvent(new UserCreatedEvent(user.getUsername(), user.getEmail(), user.getRoles()));
        return userRepository.saveUser(user);
    }

    @Override
    @Caching(evict = {
            @CacheEvict(value = "userById", key = "#id"),
            @CacheEvict(value = "userByEmail", key = "#email"),
            @CacheEvict(value = "userByUsername", key = "#username"),
            @CacheEvict(value = "users", allEntries = true)
    })
    public U updateEmailAndUsername(ID id, String email, String username) {
        U user = getUserById(id);

        // Validate email uniqueness if changing email
        if (!user.getEmail().equals(email) &&
                userRepository.existsByEmail(email)) {
            throw new DuplicateResourceException("Email already exists: " + email);
        }

        user.setUsername(username);
        user.setEmail(email);
        eventPublisher.publishEvent(new UserUpdatedEvent(user.getUsername(), user.getEmail()));
        return userRepository.saveUser(user);
    }

    @Override
    @CachePut(value = "userById", key = "#id")
    @CacheEvict(value = "users", allEntries = true)
    public U updateUser(ID id, U user) {
        U existingUser = getUserById(id);
        // Validate email uniqueness if changing email
        if (!existingUser.getEmail().equals(user.getEmail()) &&
                userRepository.existsByEmail(user.getEmail())) {
            throw new DuplicateResourceException("Email already exists: " + user.getEmail());
        }


        existingUser.setUsername(user.getUsername());
        existingUser.setEmail(user.getEmail());
        existingUser.setRoles(user.getRoles());
        // PASSWORD IS NOT UPDATED HERE IT HAS ITS OWN METHOD `updatePassword`

        eventPublisher.publishEvent(new UserUpdatedEvent(existingUser.getUsername(), existingUser.getEmail()));
        return userRepository.saveUser(existingUser);
    }

    @Override
    public U updatePassword(ID id, String encodedPassword) {
        U user = getUserById(id);

        user.setPassword(encodedPassword);
        return userRepository.saveUser(user);
    }

    @Override
    @Cacheable(value = "userExists", key = "#email")
    public boolean userExists(String email) {
        return userRepository.existsByEmail(email);
    }

    @Override
    public void deleteUser(ID id) {
        if (!userRepository.existsById(id)) {
            throw new ResourceNotFoundException("User not found with id: " + id);
        }
        U user = getUserById(id);

        evictCache("userById", id);
        evictCache("userByEmail", user.getEmail());
        evictCache("userByUsername", user.getUsername());
        evictCache("userExists", user.getEmail());
        clearCache("users");
        clearCache("adminCount");

        eventPublisher.publishEvent(new UserDeletedEvent(user.getUsername(), user.getEmail()));
        userRepository.deleteById(id);
    }

    @Override
    @Cacheable(value = "userByEmail", key = "#email")
    public U getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));
    }

    @Override
    @Cacheable(value = "users", key = "{#pageable.pageNumber, #pageable.pageSize, #username, #email, #role, #createdAfter, #createdBefore}")
    public Page<U> getAllUsers(Pageable pageable, String username, String email,
                               String role, String createdAfter, String createdBefore) {
        return userRepository.findAllWithFilters(username, email, List.of(role),
                Instant.parse(createdAfter), Instant.parse(createdBefore), pageable);
    }

    @Override
    @Cacheable(value = "allUsersList", key = "{#query, #pageable.pageSize, #pageable.pageNumber}")
    public Page<U> searchUsers(String query, Pageable pageable) {
        return userRepository.searchByQuery(query, pageable);
    }

    @Override
    public Optional<U> authenticate(String email, String rawPassword, PasswordEncoder encoder) {
        return userRepository.findByEmail(email)
                .filter(user -> encoder.matches(rawPassword, user.getPassword()));
    }

    @Override
    @Cacheable(value = "userByUsername", key = "#username")
    public U getUserByUserName(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with username: " + username));
    }

    @Override
    @Cacheable(value = "adminCount")
    public int countAdmins() {
        return userRepository.countUsersByRole("ADMIN");
    }

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