package com.ricardo.auth.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.core.RoleService;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.user.*;
import com.ricardo.auth.dto.AddRoleRequest;
import com.ricardo.auth.dto.BulkRoleUpdateRequest;
import com.ricardo.auth.dto.RemoveRoleRequest;
import com.ricardo.auth.repository.user.UserRepository;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for RoleManagementController.
 * Tests complete flow with real database and services.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class RoleManagementIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RoleService<User, AppRole, UUID> roleService;

    @Autowired
    private UserService<User, AppRole, UUID> userService;

    @Autowired
    private UserRepository<User, AppRole, UUID> userRepository;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private PasswordPolicyService passwordPolicyService;

    private User testUser;
    private User adminUser;
    private Cookie adminAccessTokenCookie;

    /**
     * Sets up.
     *
     * @throws Exception the exception
     */
    @BeforeEach
    void setUp() throws Exception {
        // Clear database
        userRepository.deleteAll();

        // Create test user with basic USER role
        testUser = new User(
                Username.valueOf("testuser"),
                Email.valueOf("testuser@example.com"),
                Password.valueOf("TestPassword123!", passwordEncoder, passwordPolicyService)
        );
        testUser.addRole(AppRole.USER);
        testUser = userRepository.saveUser(testUser);

        // Create admin user
        adminUser = new User(
                Username.valueOf("adminuser"),
                Email.valueOf("admin@example.com"),
                Password.valueOf("AdminPassword123!", passwordEncoder, passwordPolicyService)
        );
        adminUser.addRole(AppRole.ADMIN);
        adminUser = userRepository.saveUser(adminUser);

        // Generate admin access token for authentication
        String adminToken = jwtService.generateAccessToken(
                adminUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
        adminAccessTokenCookie = new Cookie("access_token", adminToken);
    }

    /**
     * Gets user roles with admin role should return success.
     *
     * @throws Exception the exception
     */
    @Test
    void getUserRoles_WithAdminRole_ShouldReturnSuccess() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(adminAccessTokenCookie)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(testUser.getId().toString()))
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.email").value("testuser@example.com"))
                .andExpect(jsonPath("$.roles[0]").value("USER"));
    }

    /**
     * Gets user roles with admin authority alternative token should return success.
     *
     * @throws Exception the exception
     */
    @Test
    void getUserRoles_WithAdminAuthority_AlternativeToken_ShouldReturnSuccess() throws Exception {
        String userReadToken = jwtService.generateAccessToken(
                adminUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
        Cookie userReadCookie = new Cookie("access_token", userReadToken);

        // When & Then
        mockMvc.perform(get("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(userReadCookie)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(testUser.getId().toString()));
    }

    /**
     * Gets user roles without permission should return forbidden.
     *
     * @throws Exception the exception
     */
    @Test
    void getUserRoles_WithoutPermission_ShouldReturnForbidden() throws Exception {
        // Given - Create user with only USER role (no admin or USER_READ)
        String userToken = jwtService.generateAccessToken(
                testUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        Cookie userCookie = new Cookie("access_token", userToken);

        // When & Then
        mockMvc.perform(get("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(userCookie)
                        .with(csrf()))
                .andExpect(status().isForbidden());
    }

    /**
     * Gets user roles without authentication should return unauthorized.
     *
     * @throws Exception the exception
     */
    @Test
    void getUserRoles_WithoutAuthentication_ShouldReturnUnauthorized() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/users/{username}/roles", testUser.getUsername()))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Add role to user with valid request should return success.
     *
     * @throws Exception the exception
     */
    @Test
    void addRoleToUser_WithValidRequest_ShouldReturnSuccess() throws Exception {
        // Given
        AddRoleRequest request = new AddRoleRequest();
        request.setRoleName("VIP");
        request.setReason("User promotion");

        // When & Then
        mockMvc.perform(post("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(adminAccessTokenCookie)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Role added successfully."))
                .andExpect(jsonPath("$.username").value(testUser.getUsername()))
                .andExpect(jsonPath("$.role").value("VIP"));

        // Verify role was actually added
        mockMvc.perform(get("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(adminAccessTokenCookie)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles").isArray())
                .andExpect(jsonPath("$.roles[?(@=='VIP')]").exists());
    }

    /**
     * Add role to user with admin authority should return success.
     *
     * @throws Exception the exception
     */
    @Test
    void addRoleToUser_WithAdminAuthority_ShouldReturnSuccess() throws Exception {
        String userWriteToken = jwtService.generateAccessToken(
                adminUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
        Cookie userWriteCookie = new Cookie("access_token", userWriteToken);

        AddRoleRequest request = new AddRoleRequest();
        request.setRoleName("VIP");
        request.setReason("User promotion");

        // When & Then
        mockMvc.perform(post("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(userWriteCookie)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        // Verify role was actually added
        mockMvc.perform(get("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(userWriteCookie)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles").isArray())
                .andExpect(jsonPath("$.roles[?(@=='VIP')]").exists());

    }

    /**
     * Add role to user with empty role name should return bad request.
     *
     * @throws Exception the exception
     */
    @Test
    void addRoleToUser_WithEmptyRoleName_ShouldReturnBadRequest() throws Exception {
        // Given
        AddRoleRequest request = new AddRoleRequest();
        request.setRoleName("");
        request.setReason("User promotion");

        // When & Then
        mockMvc.perform(post("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(adminAccessTokenCookie)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    /**
     * Add role to user with invalid role should return bad request.
     *
     * @throws Exception the exception
     */
    @Test
    void addRoleToUser_WithInvalidRole_ShouldReturnBadRequest() throws Exception {
        // Given
        AddRoleRequest request = new AddRoleRequest();
        request.setRoleName("INVALID_ROLE");
        request.setReason("User promotion");

        // When & Then
        mockMvc.perform(post("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(adminAccessTokenCookie)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());
    }

    /**
     * Add role to user without permission should return forbidden.
     *
     * @throws Exception the exception
     */
    @Test
    void addRoleToUser_WithoutPermission_ShouldReturnForbidden() throws Exception {
        // Given - Create user without proper permissions
        String userToken = jwtService.generateAccessToken(
                testUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        Cookie userCookie = new Cookie("access_token", userToken);

        AddRoleRequest request = new AddRoleRequest();
        request.setRoleName("VIP");
        request.setReason("User promotion");

        // When & Then
        mockMvc.perform(post("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(userCookie)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    /**
     * Remove role from user with valid request should return success.
     *
     * @throws Exception the exception
     */
    @Test
    void removeRoleFromUser_WithValidRequest_ShouldReturnSuccess() throws Exception {
        // First, add a role to ensure it can be removed
        AddRoleRequest addRequest = new AddRoleRequest();
        addRequest.setRoleName("VIP");
        addRequest.setReason("User promotion");
        mockMvc.perform(post("/api/users/{username}/roles", testUser.getUsername()).cookie(adminAccessTokenCookie).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(addRequest)));

        RemoveRoleRequest request = new RemoveRoleRequest();
        request.setRoleName("VIP");
        request.setReason("User demotion");

        // When & Then
        mockMvc.perform(delete("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(adminAccessTokenCookie)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Role removed successfully."))
                .andExpect(jsonPath("$.username").value(testUser.getUsername()))
                .andExpect(jsonPath("$.role").value("VIP"));

        // Verify role was actually removed
        mockMvc.perform(get("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(adminAccessTokenCookie)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles").isArray())
                .andExpect(jsonPath("$.roles[?(@=='VIP')]").doesNotExist());
    }

    /**
     * Remove role from user without permission should return forbidden.
     *
     * @throws Exception the exception
     */
    @Test
    void removeRoleFromUser_WithoutPermission_ShouldReturnForbidden() throws Exception {
        // Given - Create user without proper permissions
        String userToken = jwtService.generateAccessToken(
                testUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        Cookie userCookie = new Cookie("access_token", userToken);

        RemoveRoleRequest request = new RemoveRoleRequest();
        request.setRoleName("MODERATOR");
        request.setReason("User demotion");

        // When & Then
        mockMvc.perform(delete("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(userCookie)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    /**
     * Bulk update user roles with valid request should return success.
     *
     * @throws Exception the exception
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void bulkUpdateUserRoles_WithValidRequest_ShouldReturnSuccess() throws Exception {
        // Given
        BulkRoleUpdateRequest request = new BulkRoleUpdateRequest();
        request.setRolesToAdd(List.of("VIP"));
        request.setRolesToRemove(List.of("USER"));
        request.setReason("Bulk update");

        // When & Then
        mockMvc.perform(put("/api/users/{username}/roles/bulk", testUser.getUsername())
                        .cookie(adminAccessTokenCookie)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Roles updated successfully."))
                .andExpect(jsonPath("$.username").value(testUser.getUsername()))
                .andExpect(jsonPath("$.addedRoles").value("VIP"))
                .andExpect(jsonPath("$.removedRoles").value("USER"));

        // Verify roles were actually updated
        mockMvc.perform(get("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(adminAccessTokenCookie)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles").isArray())
                .andExpect(jsonPath("$.roles[?(@=='VIP')]").exists())
                .andExpect(jsonPath("$.roles[?(@=='USER')]").doesNotExist());
    }

    /**
     * Bulk update user roles without admin role should return forbidden.
     *
     * @throws Exception the exception
     */
    void bulkUpdateUserRoles_WithoutAdminRole_ShouldReturnForbidden() throws Exception {
        // Given - Create user with VIP role (not ADMIN)
        User vipUser = new User(
                Username.valueOf("vipuser"),
                Email.valueOf("vipuser@example.com"),
                Password.valueOf("VipPassword123!", passwordEncoder, passwordPolicyService)
        );
        vipUser.addRole(AppRole.VIP);
        vipUser = userRepository.saveUser(vipUser);

        String vipToken = jwtService.generateAccessToken(
                vipUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_VIP"))
        );
        Cookie vipCookie = new Cookie("access_token", vipToken);
        BulkRoleUpdateRequest request = new BulkRoleUpdateRequest();
        request.setRolesToAdd(List.of("MODERATOR"));
        request.setRolesToRemove(List.of("USER"));
        request.setReason("Bulk update");

        // When & Then
        mockMvc.perform(put("/api/users/{username}/roles/bulk", testUser.getUsername())
                        .cookie(vipCookie)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    /**
     * Bulk update user roles with empty request should return bad request.
     *
     * @throws Exception the exception
     */
    @Test
    void bulkUpdateUserRoles_WithEmptyRequest_ShouldReturnBadRequest() throws Exception {
        // Given
        BulkRoleUpdateRequest request = new BulkRoleUpdateRequest();
        request.setRolesToAdd(List.of());
        request.setRolesToRemove(List.of());
        request.setReason("Empty update");

        // When & Then
        mockMvc.perform(put("/api/users/{username}/roles/bulk", testUser.getUsername())
                        .cookie(adminAccessTokenCookie)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    /**
     * Gets user roles with non existent user should return not found.
     *
     * @throws Exception the exception
     */
    @Test
    void getUserRoles_WithNonExistentUser_ShouldReturnNotFound() throws Exception {
        // Given - non-existent but valid username format
        String nonExistentUsername = "nonexistentuser";

        // When & Then
        mockMvc.perform(get("/api/users/{username}/roles", nonExistentUsername)
                        .cookie(adminAccessTokenCookie)
                        .with(csrf()))
                .andExpect(status().isNotFound());
    }

    /**
     * Add role to user with long reason should return bad request.
     *
     * @throws Exception the exception
     */
    @Test
    void addRoleToUser_WithLongReason_ShouldReturnBadRequest() throws Exception {
        // Given
        AddRoleRequest request = new AddRoleRequest();
        request.setRoleName("MODERATOR");
        request.setReason("A".repeat(256)); // Exceeds 255 character limit

        // When & Then
        mockMvc.perform(post("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(adminAccessTokenCookie)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    /**
     * Remove role from user with long role name should return bad request.
     *
     * @throws Exception the exception
     */
    @Test
    void removeRoleFromUser_WithLongRoleName_ShouldReturnBadRequest() throws Exception {
        // Given
        RemoveRoleRequest request = new RemoveRoleRequest();
        request.setRoleName("A".repeat(51)); // Exceeds 50 character limit
        request.setReason("Role removal");

        // When & Then
        mockMvc.perform(delete("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(adminAccessTokenCookie)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    /**
     * Complete role management workflow should work end to end.
     *
     * @throws Exception the exception
     */
    @Test
    void completeRoleManagementWorkflow_ShouldWorkEndToEnd() throws Exception {
        // Step 1: Get initial user roles
        mockMvc.perform(get("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(adminAccessTokenCookie)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles[0]").value("USER"));

        // Step 2: Add VIP role
        AddRoleRequest addRequest = new AddRoleRequest();
        addRequest.setRoleName("VIP");
        addRequest.setReason("Promotion to VIP");

        mockMvc.perform(post("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(adminAccessTokenCookie)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(addRequest)))
                .andExpect(status().isOk());

        // Step 3: Verify role was added
        mockMvc.perform(get("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(adminAccessTokenCookie)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles").isArray())
                .andExpect(jsonPath("$.roles[?(@=='VIP')]").exists());

        // Step 4: Remove USER role
        RemoveRoleRequest removeRequest = new RemoveRoleRequest();
        removeRequest.setRoleName("USER");
        removeRequest.setReason("No longer needs user role");

        mockMvc.perform(delete("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(adminAccessTokenCookie)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(removeRequest)))
                .andExpect(status().isOk());

        // Step 5: Verify final state

        mockMvc.perform(get("/api/users/{username}/roles", testUser.getUsername())
                        .cookie(adminAccessTokenCookie)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles").isArray())
                .andExpect(jsonPath("$.roles[?(@=='VIP')]").exists())
                .andExpect(jsonPath("$.roles[?(@=='USER')]").doesNotExist());
    }

    /**
     * Gets user roles with malicious username should return bad request.
     *
     * @throws Exception the exception
     */
    @Test
    void getUserRoles_WithMaliciousUsername_ShouldReturnBadRequest() throws Exception {
        // Test SQL injection attempt
        mockMvc.perform(get("/api/users/{username}/roles", "admin'; DROP TABLE users; --")
                        .cookie(adminAccessTokenCookie)
                        .with(csrf()))
                .andExpect(status().isBadRequest());

        // Test path traversal
        mockMvc.perform(get("/api/users/{username}/roles", "../../../etc/passwd")
                        .cookie(adminAccessTokenCookie)
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }

    /**
     * Gets user roles with reserved username should return bad request.
     *
     * @throws Exception the exception
     */
    @Test
    void getUserRoles_WithReservedUsername_ShouldReturnBadRequest() throws Exception {
        // Test reserved username  
        mockMvc.perform(get("/api/users/{username}/roles", "administrator")
                        .cookie(adminAccessTokenCookie)
                        .with(csrf()))
                .andExpect(status().isBadRequest());

        mockMvc.perform(get("/api/users/{username}/roles", "root")
                        .cookie(adminAccessTokenCookie)
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }

    /**
     * Gets user roles with invalid username format should return bad request.
     *
     * @throws Exception the exception
     */
    @Test
    void getUserRoles_WithInvalidUsernameFormat_ShouldReturnBadRequest() throws Exception {
        // Too short
        mockMvc.perform(get("/api/users/{username}/roles", "ab")
                        .cookie(adminAccessTokenCookie)
                        .with(csrf()))
                .andExpect(status().isBadRequest());

        // Starts with special character
        mockMvc.perform(get("/api/users/{username}/roles", ".testuser")
                        .cookie(adminAccessTokenCookie)
                        .with(csrf()))
                .andExpect(status().isBadRequest());

        // Consecutive special characters
        mockMvc.perform(get("/api/users/{username}/roles", "test..user")
                        .cookie(adminAccessTokenCookie)
                        .with(csrf()))
                .andExpect(status().isBadRequest());

        // All numeric
        mockMvc.perform(get("/api/users/{username}/roles", "12345")
                        .cookie(adminAccessTokenCookie)
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }
}
