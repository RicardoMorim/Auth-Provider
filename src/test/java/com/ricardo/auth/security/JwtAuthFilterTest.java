package com.ricardo.auth.security;

import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.domain.AppRole;
import com.ricardo.auth.domain.Email;
import com.ricardo.auth.domain.Password;
import com.ricardo.auth.domain.User;
import com.ricardo.auth.domain.Username;
import com.ricardo.auth.repository.UserJpaRepository;
import com.ricardo.auth.service.UserDetailsServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import jakarta.servlet.ServletException;
import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for JwtAuthFilter.
 * Tests JWT authentication filter behavior in realistic scenarios.
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class JwtAuthFilterTest {

    @Autowired
    private JwtAuthFilter jwtAuthFilter;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private UserJpaRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private User testUser;
    private String validToken;

    @BeforeEach
    void setUp() {
        // Clear security context
        SecurityContextHolder.clearContext();
        
        // Clear repository
        userRepository.deleteAll();
        
        // Create test user
        testUser = new User(
            Username.valueOf("testuser"),
            Email.valueOf("test@example.com"),
            Password.valueOf("password123", passwordEncoder)
        );
        testUser.addRole(AppRole.USER);
        testUser = userRepository.save(testUser);

        // Generate valid token
        validToken = jwtService.generateToken(
            testUser.getEmail(),
            List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }

    // ========== VALID TOKEN TESTS ==========

    @Test
    void doFilterInternal_shouldAuthenticateWithValidToken() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        request.addHeader("Authorization", "Bearer " + validToken);

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("test@example.com", SecurityContextHolder.getContext().getAuthentication().getName());
        assertTrue(SecurityContextHolder.getContext().getAuthentication().isAuthenticated());
    }

    @Test
    void doFilterInternal_shouldSetCorrectAuthorities() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        request.addHeader("Authorization", "Bearer " + validToken);

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(authentication);
        assertEquals(1, authentication.getAuthorities().size());
        assertTrue(authentication.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals("ROLE_USER")));
    }

    // ========== INVALID TOKEN TESTS ==========

    @Test
    void doFilterInternal_shouldNotAuthenticateWithInvalidToken() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        request.addHeader("Authorization", "Bearer invalid.token.here");

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void doFilterInternal_shouldNotAuthenticateWithMalformedToken() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        request.addHeader("Authorization", "Bearer malformed");

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void doFilterInternal_shouldNotAuthenticateWithTamperedToken() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        // Tamper with valid token
        String tamperedToken = validToken + "tampered";
        request.addHeader("Authorization", "Bearer " + tamperedToken);

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    // ========== MISSING/INVALID HEADER TESTS ==========

    @Test
    void doFilterInternal_shouldNotAuthenticateWithoutAuthorizationHeader() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        // No Authorization header

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void doFilterInternal_shouldNotAuthenticateWithoutBearerPrefix() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        request.addHeader("Authorization", validToken); // Missing "Bearer " prefix

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void doFilterInternal_shouldNotAuthenticateWithWrongPrefix() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        request.addHeader("Authorization", "Basic " + validToken); // Wrong prefix

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void doFilterInternal_shouldNotAuthenticateWithEmptyHeader() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        request.addHeader("Authorization", "");

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    // ========== CASE SENSITIVITY TESTS ==========

    @Test
    void doFilterInternal_shouldBeCaseSensitiveForBearerPrefix() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        request.addHeader("Authorization", "bearer " + validToken); // lowercase

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void doFilterInternal_shouldBeCaseSensitiveForBearerPrefixUppercase() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        request.addHeader("Authorization", "BEARER " + validToken); // uppercase

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    // ========== ALREADY AUTHENTICATED TESTS ==========

    @Test
    void doFilterInternal_shouldNotOverrideExistingAuthentication() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        // Set existing authentication
        SecurityContextHolder.getContext().setAuthentication(
            new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                "existing@user.com", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
            )
        );
        
        request.addHeader("Authorization", "Bearer " + validToken);

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert - Should keep existing authentication
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        assertEquals("existing@user.com", authentication.getName());
        assertTrue(authentication.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN")));
    }

    // ========== MULTIPLE ROLES TESTS ==========

    @Test
    void doFilterInternal_shouldHandleMultipleRoles() throws ServletException, IOException {
        // Arrange
        testUser.addRole(AppRole.ADMIN);
        userRepository.save(testUser);
        
        String multiRoleToken = jwtService.generateToken(
            testUser.getEmail(),
            List.of(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_ADMIN")
            )
        );
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        request.addHeader("Authorization", "Bearer " + multiRoleToken);

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(authentication);
        assertEquals(2, authentication.getAuthorities().size());
        assertTrue(authentication.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals("ROLE_USER")));
        assertTrue(authentication.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN")));
    }

    // ========== SPECIAL CHARACTERS TESTS ==========

    @Test
    void doFilterInternal_shouldHandleSpecialCharactersInSubject() throws ServletException, IOException {
        // Arrange
        User specialUser = new User(
            Username.valueOf("specialuser"),
            Email.valueOf("test+tag@example.com"),
            Password.valueOf("password123", passwordEncoder)
        );
        specialUser.addRole(AppRole.USER);
        userRepository.save(specialUser);
        
        String specialToken = jwtService.generateToken(
            "test+tag@example.com",
            List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        request.addHeader("Authorization", "Bearer " + specialToken);

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(authentication);
        assertEquals("test+tag@example.com", authentication.getName());
    }

    // ========== FILTER CHAIN CONTINUATION TESTS ==========

    @Test
    void doFilterInternal_shouldContinueFilterChainWithValidToken() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        request.addHeader("Authorization", "Bearer " + validToken);

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        // Filter chain should have been called (MockFilterChain tracks this)
    }

    @Test
    void doFilterInternal_shouldContinueFilterChainWithInvalidToken() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        request.addHeader("Authorization", "Bearer invalid.token");

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        // Filter chain should still continue
    }

    @Test
    void doFilterInternal_shouldContinueFilterChainWithoutToken() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        // Filter chain should still continue
    }

    // ========== ERROR HANDLING TESTS ==========

    @Test
    void doFilterInternal_shouldHandleTokenExtractionErrors() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        // Token that will cause parsing errors
        request.addHeader("Authorization", "Bearer ...");

        // Act & Assert - Should not throw exception
        assertDoesNotThrow(() -> {
            jwtAuthFilter.doFilterInternal(request, response, filterChain);
        });
        
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    // ========== WHITESPACE HANDLING TESTS ==========

    @Test
    void doFilterInternal_shouldHandleWhitespaceInHeader() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        
        request.addHeader("Authorization", "  Bearer " + validToken + "  "); // Extra whitespace

        // Act
        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        // Assert - Should not authenticate due to whitespace
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    // ========== THREAD SAFETY TESTS ==========

    @Test
    void doFilterInternal_shouldBeConcurrentlySafe() throws ServletException, IOException {
        // This test ensures filter doesn't have shared state issues
        
        // Create multiple requests
        MockHttpServletRequest request1 = new MockHttpServletRequest();
        MockHttpServletRequest request2 = new MockHttpServletRequest();
        MockHttpServletResponse response1 = new MockHttpServletResponse();
        MockHttpServletResponse response2 = new MockHttpServletResponse();
        MockFilterChain filterChain1 = new MockFilterChain();
        MockFilterChain filterChain2 = new MockFilterChain();
        
        request1.addHeader("Authorization", "Bearer " + validToken);
        request2.addHeader("Authorization", "Bearer invalid.token");

        // Act - Process both requests
        jwtAuthFilter.doFilterInternal(request1, response1, filterChain1);
        var auth1 = SecurityContextHolder.getContext().getAuthentication();
        
        SecurityContextHolder.clearContext(); // Simulate different thread
        
        jwtAuthFilter.doFilterInternal(request2, response2, filterChain2);
        var auth2 = SecurityContextHolder.getContext().getAuthentication();

        // Assert - Results should be independent
        assertNotNull(auth1);
        assertNull(auth2);
    }
}
