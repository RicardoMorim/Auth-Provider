package com.ricardo.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.domain.user.*;
import com.ricardo.auth.dto.CreateUserRequestDTO;
import com.ricardo.auth.dto.LoginRequestDTO;
import com.ricardo.auth.repository.user.DefaultUserJpaRepository;
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
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * The type Security integration test.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class SecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private PasswordPolicyService passwordPolicyService;

    @Autowired
    private DefaultUserJpaRepository userRepository;

    @Autowired
    private JwtService jwtService;

    private User testUser;
    private User adminUser;
    private Cookie accessTokenCookie;

    /**
     * Sets up.
     *
     * @throws Exception the exception
     */
    @BeforeEach
    void setUp() throws Exception {
        userRepository.deleteAll();

        // Create test user
        testUser = new User(
                Username.valueOf("testuser"),
                Email.valueOf("test@example.com"),
                Password.valueOf("Password@123", passwordEncoder, passwordPolicyService)
        );
        testUser.addRole(AppRole.USER);
        testUser = userRepository.save(testUser);

        // Create admin user
        adminUser = new User(
                Username.valueOf("adminuser"),
                Email.valueOf("admin@example.com"),
                Password.valueOf("Password@123", passwordEncoder, passwordPolicyService)
        );
        adminUser.addRole(AppRole.ADMIN);
        adminUser = userRepository.save(adminUser);

        // Perform login to get access token cookie
        LoginRequestDTO loginRequest = new LoginRequestDTO(testUser.getEmail(), "Password@123");
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        // Extract access token cookie from response
        accessTokenCookie = loginResult.getResponse().getCookie("access_token");
    }

    // ========== PUBLIC ENDPOINT TESTS ==========

    /**
     * Should allow public access to login.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldAllowPublicAccessToLogin() throws Exception {
        LoginRequestDTO loginRequest = new LoginRequestDTO("nonexistent@user.com", "wrongpassword");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Should allow public access to user creation.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldAllowPublicAccessToUserCreation() throws Exception {
        CreateUserRequestDTO createRequest = new CreateUserRequestDTO(
                "newuser", "newuser@example.com", "Password@123"
        );

        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createRequest)))
                .andExpect(status().isCreated());
    }

    // ========== AUTHENTICATION TESTS ==========

    /**
     * Should deny access to me endpoint for anonymous user.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldDenyAccessToMeEndpointForAnonymousUser() throws Exception {
        mockMvc.perform(get("/api/auth/me").with(csrf()))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Should allow access to me endpoint for authenticated user.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldAllowAccessToMeEndpointForAuthenticatedUser() throws Exception {
        mockMvc.perform(get("/api/auth/me").with(csrf()).cookie(accessTokenCookie))
                .andExpect(status().isOk());
    }

    /**
     * Should successfully login and return token.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldSuccessfullyLoginAndReturnToken() throws Exception {
        // Arrange
        LoginRequestDTO loginRequest = new LoginRequestDTO("test@example.com", "Password@123");

        // Act & Assert
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("access_token"))
                .andExpect(cookie().exists("refresh_token"))
                .andReturn();

        // Extract cookies from response
        Cookie accessTokenCookie = result.getResponse().getCookie("access_token");
        Cookie refreshTokenCookie = result.getResponse().getCookie("refresh_token");

        // Verify token validity
        assertTrue(jwtService.isTokenValid(accessTokenCookie.getValue()));
    }

    /**
     * Should reject invalid credentials.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldRejectInvalidCredentials() throws Exception {
        LoginRequestDTO loginRequest = new LoginRequestDTO("test@example.com", "wrongpassword");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }

    // ========== JWT TOKEN TESTS ==========

    /**
     * Should authenticate with valid jwt token.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldAuthenticateWithValidJwtToken() throws Exception {
        String token = jwtService.generateAccessToken(
                testUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        mockMvc.perform(get("/api/auth/me").with(csrf()).cookie(accessTokenCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.roles").isArray());
    }

    /**
     * Should reject invalid jwt token.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldRejectInvalidJwtToken() throws Exception {
        String invalidToken = "invalid.jwt.token";

        mockMvc.perform(get("/api/auth/me").with(csrf())
                        .cookie(new Cookie("access_token", invalidToken)))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Should reject malformed jwt token.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldRejectMalformedJwtToken() throws Exception {
        String malformedToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.malformed";

        mockMvc.perform(get("/api/auth/me").with(csrf())
                        .cookie(new Cookie("access_token", malformedToken)))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Should reject empty authorization header.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldRejectEmptyCookie() throws Exception {
        Cookie cookie = new Cookie("access_token", "");
        mockMvc.perform(get("/api/auth/me").with(csrf()).cookie(cookie))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Should reject request without authorization header.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldRejectRequestWithoutAuthorizationHeader() throws Exception {
        mockMvc.perform(get("/api/auth/me").with(csrf()))
                .andExpect(status().isUnauthorized());
    }

    // ========== ROLE-BASED ACCESS CONTROL TESTS ==========

    /**
     * Should not allow access to delete for admin.
     *
     * @throws Exception the exception
     */
    @Test
    @WithMockUser(roles = "USER")
    void shouldNotAllowAccessToDeleteForAdmin() throws Exception {
        CreateUserRequestDTO createRequest = new CreateUserRequestDTO(
                "testusera", "testusera@gmail.com", "Password@123"
        );

        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createRequest)))
                .andExpect(status().isCreated());

        Cookie accessTokenCookie = new Cookie("access_token", jwtService.generateAccessToken(
                testUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        ));

        UUID testUserId = testUser.getId();

        // Attempt to delete a user with an ID that does not match the authenticated user
        // This should be forbidden for a regular user
        mockMvc.perform(delete("/api/users/delete/" + UUID.randomUUID().toString()).cookie(accessTokenCookie))
                .andExpect(status().isForbidden());
    }

    /**
     * Should allow access to delete for admin.
     *
     * @throws Exception the exception
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void shouldAllowAccessToDeleteForAdmin() throws Exception {
        CreateUserRequestDTO createRequest = new CreateUserRequestDTO(
                "testuserabc", "testuserabc@gmail.com", "Password@123"
        );

        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createRequest)))
                .andExpect(status().isCreated());

        Cookie accessTokenCookie = new Cookie("access_token", jwtService.generateAccessToken(
                adminUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        ));

        mockMvc.perform(delete("/api/users/delete/" + (testUser.getUsername())).with(csrf()).cookie(accessTokenCookie))
                .andExpect(status().isNoContent());
    }

    /**
     * Should allow user role to access user endpoints.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldAllowUserRoleToAccessUserEndpoints() throws Exception {
        String token = jwtService.generateAccessToken(
                testUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        Cookie accessTokenCookie = new Cookie("access_token", token);

        mockMvc.perform(get("/api/auth/me").with(csrf()).cookie(accessTokenCookie))
                .andExpect(status().isOk());
    }

    /**
     * Should allow admin role to access admin endpoints.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldAllowAdminRoleToAccessAdminEndpoints() throws Exception {
        String token = jwtService.generateAccessToken(
                adminUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );

        Cookie accessTokenCookie = new Cookie("access_token", token);

        mockMvc.perform(get("/api/users/" + testUser.getUsername()).with(csrf()).cookie(accessTokenCookie))
                .andExpect(status().isOk());
    }

    /**
     * Should deny user role access to admin endpoints.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldDenyUserRoleAccessToAdminEndpoints() throws Exception {
        String token = jwtService.generateAccessToken(
                testUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        Cookie accessTokenCookie = new Cookie("access_token", token);

        mockMvc.perform(delete("/api/users/delete/" + adminUser.getId()).with(csrf()).cookie(accessTokenCookie))
                .andExpect(status().isForbidden());
    }

    /**
     * Should deny access with tampered token.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldDenyAccessWithTamperedToken() throws Exception {
        String tamperedToken = jwtService.generateAccessToken(
                testUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        ) + "tampered";

        mockMvc.perform(get("/api/auth/me").with(csrf())
                .cookie(new Cookie("access_token", tamperedToken)))
                .andExpect(status().isUnauthorized());
    }

    // ========== AUTHORIZATION EDGE CASES ==========

    /**
     * Should handle token with invalid roles.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldHandleTokenWithInvalidRoles() throws Exception {
        String token = jwtService.generateAccessToken(
                testUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_INVALID"))
        );

        Cookie accessTokenCookie = new Cookie("access_token", token);

        mockMvc.perform(get("/api/auth/me").with(csrf()).cookie(accessTokenCookie))
                .andExpect(status().isOk());

        mockMvc.perform(delete("/api/users/delete/" + adminUser.getId().toString()).with(csrf()).cookie(accessTokenCookie))
                .andExpect(status().isForbidden());
    }

    /**
     * Should handle multiple roles.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldHandleMultipleRoles() throws Exception {
        adminUser.addRole(AppRole.USER);
        userRepository.save(adminUser);

        String token = jwtService.generateAccessToken(
                adminUser.getEmail(),
                List.of(
                        new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN")
                )
        );

        Cookie accessTokenCookie = new Cookie("access_token", token);

        mockMvc.perform(get("/api/auth/me").with(csrf()).cookie(accessTokenCookie))
                .andExpect(status().isOk());

        mockMvc.perform(delete("/api/users/delete/" + testUser.getUsername()).with(csrf()).cookie(accessTokenCookie))
                .andExpect(status().isNoContent());
    }

    // ========== HTTP METHOD SECURITY TESTS ==========

    /**
     * Should secure all http methods for protected endpoints.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldSecureAllHttpMethodsForProtectedEndpoints() throws Exception {
        String protectedEndpoint = "/api/auth/me";

        mockMvc.perform(get(protectedEndpoint).with(csrf()))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post(protectedEndpoint).with(csrf()))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(put(protectedEndpoint).with(csrf()))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(delete(protectedEndpoint).with(csrf()))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(patch(protectedEndpoint).with(csrf()))
                .andExpect(status().isUnauthorized());
    }

    // ========== ERROR HANDLING TESTS ==========

    /**
     * Should return json error for unauthorized requests.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldReturnJsonErrorForUnauthorizedRequests() throws Exception {
        Cookie invalidCookie = new Cookie("access_token", "invalid.token");
        mockMvc.perform(get("/api/auth/me").with(csrf()).cookie(invalidCookie)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Should return json error for forbidden requests.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldReturnJsonErrorForForbiddenRequests() throws Exception {
        String token = jwtService.generateAccessToken(
                testUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        Cookie accessTokenCookie = new Cookie("access_token", token);

        mockMvc.perform(delete("/api/users/delete/" + adminUser.getId().toString()).with(csrf()).cookie(accessTokenCookie)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }

    // ========== INTEGRATION WORKFLOW TESTS ==========

    /**
     * Should complete full authentication workflow.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldCompleteFullAuthenticationWorkflow() throws Exception {
        // Step 1: Login and get tokens via cookies
        LoginRequestDTO loginRequest = new LoginRequestDTO("test@example.com", "Password@123");
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        Cookie accessTokenCookie = loginResult.getResponse().getCookie("access_token");
        assertNotNull(accessTokenCookie, "Access token cookie not present");

        mockMvc.perform(get("/api/auth/me").with(csrf())
                        .cookie(accessTokenCookie))
                .andExpect(status().isOk());
    }

    /**
     * Should complete full admin workflow.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldCompleteFullAdminWorkflow() throws Exception {
        // Step 1: Login as admin and get tokens via cookies
        LoginRequestDTO loginRequest = new LoginRequestDTO("admin@example.com", "Password@123");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("access_token"))
                .andExpect(cookie().exists("refresh_token"))
                .andReturn();

        // Extract cookies
        Cookie accessTokenCookie = loginResult.getResponse().getCookie("access_token");

        // Step 2: Use admin token to access user management
        mockMvc.perform(get("/api/users/" + testUser.getUsername()).with(csrf())
                        .cookie(accessTokenCookie))
                .andExpect(status().isOk());

        // Step 3: Use admin token to delete user
        mockMvc.perform(delete("/api/users/delete/" + testUser.getUsername()).with(csrf())
                        .cookie(accessTokenCookie))
                .andExpect(status().isNoContent());
    }

    // ========== BOUNDARY AND EDGE CASE TESTS ==========

    /**
     * Should handle very long tokens.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldHandleVeryLongTokens() throws Exception {
        String longSubject = "a".repeat(1000) + "@example.com";
        String token = jwtService.generateAccessToken(
                longSubject,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        Cookie accessTokenCookie = new Cookie("access_token", token);

        mockMvc.perform(get("/api/auth/me").with(csrf()).cookie(accessTokenCookie))
                .andExpect(status().isOk());
    }

    /**
     * Should handle special characters in token.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldHandleSpecialCharactersInToken() throws Exception {
        String specialSubject = "test+user@example.com";
        String token = jwtService.generateAccessToken(
                specialSubject,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        Cookie accessTokenCookie = new Cookie("access_token", token);
        mockMvc.perform(get("/api/auth/me").with(csrf()).cookie(accessTokenCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(specialSubject));
    }
}