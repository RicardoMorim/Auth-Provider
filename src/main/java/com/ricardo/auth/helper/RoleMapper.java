package com.ricardo.auth.helper;

import com.ricardo.auth.core.Role;

/**
 * Interface for mapping string role values from the database to typed role instances.
 * This provides type-safe role conversion for PostgreSQL repository implementations.
 *
 * @param <R> the role type that extends Role
 */
@FunctionalInterface
public interface RoleMapper<R extends Role> {
    
    /**
     * Maps a string role value from the database to a typed role instance.
     * 
     * @param roleString the role string from the database (e.g., "USER", "ADMIN")
     * @return the typed role instance
     * @throws RoleMappingException if the role string cannot be mapped to a valid role
     * @throws IllegalArgumentException if roleString is null or empty
     */
    R mapRole(String roleString) throws RoleMappingException;
    
    /**
     * Exception thrown when role mapping fails.
     */
    class RoleMappingException extends RuntimeException {
        public RoleMappingException(String message) {
            super(message);
        }
        
        public RoleMappingException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
