package com.ricardo.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.domain.user.*;
import com.ricardo.auth.dto.CreateUserRequestDTO;
import com.ricardo.auth.dto.LoginRequestDTO;
import com.ricardo.auth.dto.TokenResponse;
import com.ricardo.auth.repository.user.DefaultUserJpaRepository;
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

import static org.junit.jupiter.api.Assertions.assertTrue;
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

    /**
     * Sets up.
     */
    @BeforeEach
    void setUp() {
        userRepository.deleteAll();

        // Create test user
        testUser = new User(
                Username.valueOf("testuser"),
                Email.valueOf("test@example.com"),
                Password.valueOf("Password@123", passwordEncoder, passwordPolicyService)
        );
        testUser.addRole(AppRole.USER);
        userRepository.save(testUser);

        // Create admin user
        adminUser = new User(
                Username.valueOf("adminuser"),
                Email.valueOf("admin@example.com"),
                Password.valueOf("Password@123", passwordEncoder, passwordPolicyService)
        );
        adminUser.addRole(AppRole.ADMIN);
        userRepository.save(adminUser);
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
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Should allow access to me endpoint for authenticated user.
     *
     * @throws Exception the exception
     */
    @Test
    @WithMockUser(username = "test@user.com", roles = {"USER"})
    void shouldAllowAccessToMeEndpointForAuthenticatedUser() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
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
                .andExpect(jsonPath("$.accessToken").exists()) // ✅ Changed from $.token
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").exists()) // ✅ Added refresh token check
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn();

        // Verify token is valid
        String response = result.getResponse().getContentAsString();
        TokenResponse tokenResponse = objectMapper.readValue(response, TokenResponse.class); // ✅ Changed from TokenDTO
        assertTrue(jwtService.isTokenValid(tokenResponse.getAccessToken())); // ✅ Use accessToken
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

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("test@example.com"))
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

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + invalidToken))
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

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + malformedToken))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Should reject token without bearer prefix.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldRejectTokenWithoutBearerPrefix() throws Exception {
        String token = jwtService.generateAccessToken(
                testUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", token))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Should reject empty authorization header.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldRejectEmptyAuthorizationHeader() throws Exception {
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", ""))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Should reject request without authorization header.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldRejectRequestWithoutAuthorizationHeader() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
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

        mockMvc.perform(delete("/api/users/delete/" + (testUser.getId() + 1)))
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

        mockMvc.perform(delete("/api/users/delete/" + (testUser.getId() + 1)))
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

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + token))
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

        mockMvc.perform(get("/api/users/" + testUser.getId())
                        .header("Authorization", "Bearer " + token))
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

        mockMvc.perform(delete("/api/users/delete/" + adminUser.getId())
                        .header("Authorization", "Bearer " + token))
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

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + tamperedToken))
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

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        mockMvc.perform(delete("/api/users/delete/" + adminUser.getId())
                        .header("Authorization", "Bearer " + token))
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

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        mockMvc.perform(delete("/api/users/delete/" + testUser.getId())
                        .header("Authorization", "Bearer " + token))
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

        mockMvc.perform(get(protectedEndpoint))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post(protectedEndpoint))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(put(protectedEndpoint))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(delete(protectedEndpoint))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(patch(protectedEndpoint))
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
        mockMvc.perform(get("/api/auth/me")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));
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

        mockMvc.perform(delete("/api/users/delete/" + adminUser.getId())
                        .header("Authorization", "Bearer " + token)
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
        // Step 1: Login and get token
        LoginRequestDTO loginRequest = new LoginRequestDTO("test@example.com", "Password@123");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String loginResponse = loginResult.getResponse().getContentAsString();
        TokenResponse tokenResponse = objectMapper.readValue(loginResponse, TokenResponse.class); // ✅ Changed from TokenDTO

        // Step 2: Use token to access protected endpoint
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + tokenResponse.getAccessToken())) // ✅ Use accessToken
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("testuser"));

        // Step 3: Try to access admin endpoint (should fail for USER role)
        mockMvc.perform(delete("/api/users/delete/" + adminUser.getId())
                        .header("Authorization", "Bearer " + tokenResponse.getAccessToken()))
                .andExpect(status().isForbidden());
    }

    /**
     * Should complete full admin workflow.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldCompleteFullAdminWorkflow() throws Exception {
        // Step 1: Login as admin and get token
        LoginRequestDTO loginRequest = new LoginRequestDTO("admin@example.com", "Password@123");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String loginResponse = loginResult.getResponse().getContentAsString();
        TokenResponse tokenResponse = objectMapper.readValue(loginResponse, TokenResponse.class); // ✅ Changed from TokenDTO

        // Step 2: Use admin token to access user management
        mockMvc.perform(get("/api/users/" + testUser.getId())
                        .header("Authorization", "Bearer " + tokenResponse.getAccessToken()))
                .andExpect(status().isOk());

        // Step 3: Use admin token to delete user
        mockMvc.perform(delete("/api/users/delete/" + testUser.getId())
                        .header("Authorization", "Bearer " + tokenResponse.getAccessToken()))
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

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + token))
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

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value(specialSubject));
    }

    /**
     * Should handle case insensitive bearer header.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldHandleCaseInsensitiveBearerHeader() throws Exception {
        String token = jwtService.generateAccessToken(
                testUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "bearer " + token))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "BEARER " + token))
                .andExpect(status().isUnauthorized());
    }
}