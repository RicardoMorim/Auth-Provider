package com.ricardo.auth.helper;

import com.ricardo.auth.domain.user.AppRole;

/**
 * Default implementation of RoleMapper for AppRole enum.
 * Provides type-safe conversion from string role values to AppRole instances.
 *
 */
public class AppRoleMapper implements RoleMapper<AppRole> {
    
    @Override
    public AppRole mapRole(String roleString) throws RoleMappingException {
        if (roleString == null || roleString.trim().isEmpty()) {
            throw new IllegalArgumentException("Role string cannot be null or empty");
        }
        
        try {
            return AppRole.valueOf(roleString.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new RoleMappingException("Unknown role: " + roleString, e);
        }
    }
}
