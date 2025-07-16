package com.ricardo.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.domain.user.*;
import com.ricardo.auth.dto.CreateUserRequestDTO;
import com.ricardo.auth.dto.LoginRequestDTO;
import com.ricardo.auth.dto.TokenResponse; // ✅ Changed from TokenDTO
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

    @Test
    void shouldAllowPublicAccessToLogin() throws Exception {
        LoginRequestDTO loginRequest = new LoginRequestDTO("nonexistent@user.com", "wrongpassword");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }

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

    @Test
    void shouldDenyAccessToMeEndpointForAnonymousUser() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "test@user.com", roles = {"USER"})
    void shouldAllowAccessToMeEndpointForAuthenticatedUser() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isOk());
    }

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

    @Test
    void shouldRejectInvalidCredentials() throws Exception {
        LoginRequestDTO loginRequest = new LoginRequestDTO("test@example.com", "wrongpassword");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }

    // ========== JWT TOKEN TESTS ==========

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

    @Test
    void shouldRejectInvalidJwtToken() throws Exception {
        String invalidToken = "invalid.jwt.token";

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + invalidToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectMalformedJwtToken() throws Exception {
        String malformedToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.malformed";

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + malformedToken))
                .andExpect(status().isUnauthorized());
    }

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

    @Test
    void shouldRejectEmptyAuthorizationHeader() throws Exception {
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", ""))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectRequestWithoutAuthorizationHeader() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    // ========== ROLE-BASED ACCESS CONTROL TESTS ==========

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

    @Test
    void shouldReturnJsonErrorForUnauthorizedRequests() throws Exception {
        mockMvc.perform(get("/api/auth/me")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));
    }

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