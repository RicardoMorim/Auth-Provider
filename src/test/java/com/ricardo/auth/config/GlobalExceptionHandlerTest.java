package com.ricardo.auth.config;

import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.domain.exceptions.DuplicateResourceException;
import com.ricardo.auth.domain.exceptions.ResourceNotFoundException;
import com.ricardo.auth.domain.user.Email;
import com.ricardo.auth.domain.user.Password;
import com.ricardo.auth.domain.user.User;
import com.ricardo.auth.domain.user.Username;
import com.ricardo.auth.dto.ErrorResponse;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.WebRequest;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Tests for GlobalExceptionHandler to ensure proper error handling and responses.
 * Tests exception mapping, HTTP status codes, and error message formatting.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class GlobalExceptionHandlerTest {

    /**
     * The Jwt service.
     */
    @Autowired
    JwtService jwtService;
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private GlobalExceptionHandler globalExceptionHandler;
    // ========== DOMAIN EXCEPTION TESTS ==========

    /**
     * Should handle resource not found exception.
     */
    @Test
    void shouldHandleResourceNotFoundException() {
        // Arrange
        ResourceNotFoundException exception = new ResourceNotFoundException("User not found");
        WebRequest request = null; // Can be null for unit test

        // Act
        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleResourceNotFoundException(exception, request);

        // Assert
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("User not found", response.getBody().getMessage());
    }

    /**
     * Should handle duplicate resource exception.
     */
    @Test
    void shouldHandleDuplicateResourceException() {
        // Arrange
        DuplicateResourceException exception = new DuplicateResourceException("Email already exists");
        WebRequest request = null;

        // Act
        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleDuplicateResourceException(exception, request);

        // Assert
        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Email already exists", response.getBody().getMessage());
    }

    /**
     * Should handle illegal argument exception.
     */
    @Test
    void shouldHandleIllegalArgumentException() {
        // Arrange - This covers validation from domain value objects
        IllegalArgumentException exception = new IllegalArgumentException("Invalid email format");
        WebRequest request = null;

        // Act
        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleIllegalArgumentException(exception, request);

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Invalid email format", response.getBody().getMessage());
    }

    // ========== SECURITY EXCEPTION TESTS ==========

    /**
     * Should handle authentication exception.
     */
    @Test
    void shouldHandleAuthenticationException() {
        // Arrange
        AuthenticationException exception = new BadCredentialsException("Invalid credentials");
        WebRequest request = null;

        // Act
        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleAuthenticationException(exception, request);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Authentication Failed: Invalid credentials", response.getBody().getMessage());
    }

    /**
     * Should handle access denied exception.
     */
    @Test
    void shouldHandleAccessDeniedException() {
        // Arrange
        AccessDeniedException exception = new AccessDeniedException("Access denied");
        WebRequest request = null;

        // Act
        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleAccessDeniedException(exception, request);

        // Assert
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Access Denied: You do not have permission to perform this action.", response.getBody().getMessage());
    }

    // ========== GENERIC EXCEPTION TESTS ==========

    /**
     * Should handle generic exception.
     */
    @Test
    void shouldHandleGenericException() {
        // Arrange
        Exception exception = new Exception("Unexpected error occurred");
        WebRequest request = null;

        // Act
        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleGlobalException(exception, request);

        // Assert
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("An internal server error occurred. Please try again later.", response.getBody().getMessage());
    }

    // ========== INTEGRATION TESTS WITH ACTUAL ENDPOINTS ==========

    /**
     * Should return not found for non existent user.
     *
     * @throws Exception the exception
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void shouldReturnNotFoundForNonExistentUser() throws Exception {

        User adminUser = new User(Username.valueOf("admin"),
                Email.valueOf("admin@example.com"),
                Password.fromHash("admin123"));


        String token = jwtService.generateAccessToken(
                adminUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );

        Cookie accessTokenCookie = new Cookie("access_token", token);

        // Act & Assert
        mockMvc.perform(get("/api/users/" + UUID.randomUUID().toString()).cookie(accessTokenCookie)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.message").exists());
    }

    /**
     * Should return bad request for invalid user data.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldReturnBadRequestForInvalidUserData() throws Exception {
        // Arrange - Create user with invalid data
        String invalidUserJson = """
                {
                    "username": "",
                    "email": "invalid-email",
                    "password": "123"
                }
                """;

        // Act & Assert
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(invalidUserJson))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.message").exists());
    }

    /**
     * Should return conflict for duplicate email.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldReturnConflictForDuplicateEmail() throws Exception {
        // Arrange - Create first user
        String userJson = """
                {
                    "username": "testuser",
                    "email": "test@example.com",
                    "password": "Password@123"
                }
                """;

        // Create first user
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(userJson))
                .andExpect(status().isCreated());

        // Act & Assert - Try to create user with same email
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(userJson))
                .andExpect(status().isConflict())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.message").exists());
    }

    /**
     * Should return unauthorized for invalid login.
     *
     * @throws Exception the exception
     */
    @Test
    void shouldReturnUnauthorizedForInvalidLogin() throws Exception {
        // Arrange
        String invalidLoginJson = """
                {
                    "email": "nonexistent@example.com",
                    "password": "wrongpassword"
                }
                """;

        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(invalidLoginJson))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.message").exists());
    }

    // ========== ERROR MESSAGE FORMATTING TESTS ==========

    /**
     * Should return properly formatted error response.
     */
    @Test
    void shouldReturnProperlyFormattedErrorResponse() {
        // Arrange
        String errorMessage = "Test error message";
        ResourceNotFoundException exception = new ResourceNotFoundException(errorMessage);
        WebRequest request = null;

        // Act
        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleResourceNotFoundException(exception, request);

        // Assert
        assertNotNull(response.getBody());
        assertEquals(errorMessage, response.getBody().getMessage());

        // Verify error response structure
        ErrorResponse errorResponse = response.getBody();
        assertNotNull(errorResponse.getMessage());
        assertFalse(errorResponse.getMessage().isEmpty());
    }

    /**
     * Should handle null exception message.
     */
    @Test
    void shouldHandleNullExceptionMessage() {
        // Arrange
        ResourceNotFoundException exception = new ResourceNotFoundException("Username not found");
        WebRequest request = null;

        // Act
        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleResourceNotFoundException(exception, request);

        // Assert
        assertNotNull(response.getBody());
        // Should handle null message gracefully
        assertNotNull(response.getBody().getMessage());
    }

    /**
     * Should handle empty exception message.
     */
    @Test
    void shouldHandleEmptyExceptionMessage() {
        // Arrange
        ResourceNotFoundException exception = new ResourceNotFoundException("");
        WebRequest request = null;

        // Act
        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleResourceNotFoundException(exception, request);

        // Assert
        assertNotNull(response.getBody());
        assertEquals("", response.getBody().getMessage());
    }

    // ========== CONTENT TYPE TESTS ==========

    /**
     * Should return json content type.
     *
     * @throws Exception the exception
     */
    @Test
    @WithMockUser(roles = "ADMIN")
    void shouldReturnJsonContentType() throws Exception {
        User adminUser = new User(Username.valueOf("admin"),
                Email.valueOf("admin@example.com"),
                Password.fromHash("admin123"));


        String token = jwtService.generateAccessToken(
                adminUser.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );

        Cookie accessTokenCookie = new Cookie("access_token", token);

        // Act & Assert - Test that error responses are JSON
        mockMvc.perform(get("/api/users/" + UUID.randomUUID().toString()).cookie(accessTokenCookie))
                .andExpect(status().isNotFound())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));
    }

    // ========== EDGE CASE TESTS ==========

    /**
     * Should handle very long error messages.
     */
    @Test
    void shouldHandleVeryLongErrorMessages() {
        // Arrange
        String longMessage = "A".repeat(10000); // Very long error message
        ResourceNotFoundException exception = new ResourceNotFoundException(longMessage);
        WebRequest request = null;

        // Act
        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleResourceNotFoundException(exception, request);

        // Assert
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(longMessage, response.getBody().getMessage());
    }

    /**
     * Should handle special characters in error messages.
     */
    @Test
    void shouldHandleSpecialCharactersInErrorMessages() {
        // Arrange
        String messageWithSpecialChars = "Error: User 'test@example.com' not found! 🚫";
        ResourceNotFoundException exception = new ResourceNotFoundException(messageWithSpecialChars);
        WebRequest request = null;

        // Act
        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleResourceNotFoundException(exception, request);

        // Assert
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(messageWithSpecialChars, response.getBody().getMessage());
    }

    // ========== SECURITY INTEGRATION TESTS ==========

    /**
     * Should not expose internal details.
     */
    @Test
    void shouldNotExposeInternalDetails() {
        // Arrange
        Exception internalException = new Exception("Internal database connection failed with sensitive info");
        WebRequest request = null;

        // Act
        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleGlobalException(internalException, request);

        // Assert
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(response.getBody());

        // Should return generic message, not internal details
        assertEquals("An internal server error occurred. Please try again later.", response.getBody().getMessage());
        assertNotEquals("Internal database connection failed with sensitive info", response.getBody().getMessage());
    }

    /**
     * Should handle multiple exception types.
     */
    @Test
    void shouldHandleMultipleExceptionTypes() {
        // Test that different exception types return different status codes
        WebRequest request = null;

        // Arrange & Act
        ResponseEntity<ErrorResponse> notFound = globalExceptionHandler.handleResourceNotFoundException(
                new ResourceNotFoundException("Not found"), request);
        ResponseEntity<ErrorResponse> badRequest = globalExceptionHandler.handleIllegalArgumentException(
                new IllegalArgumentException("Bad request"), request);
        ResponseEntity<ErrorResponse> conflict = globalExceptionHandler.handleDuplicateResourceException(
                new DuplicateResourceException("Conflict"), request);
        ResponseEntity<ErrorResponse> unauthorized = globalExceptionHandler.handleAuthenticationException(
                new BadCredentialsException("Unauthorized"), request);

        // Assert
        assertEquals(HttpStatus.NOT_FOUND, notFound.getStatusCode());
        assertEquals(HttpStatus.BAD_REQUEST, badRequest.getStatusCode());
        assertEquals(HttpStatus.CONFLICT, conflict.getStatusCode());
        assertEquals(HttpStatus.UNAUTHORIZED, unauthorized.getStatusCode());
    }

    // ========== DOMAIN VALUE OBJECT VALIDATION TESTS ==========

    /**
     * Should handle email validation error.
     */
    @Test
    void shouldHandleEmailValidationError() {
        // Arrange - IllegalArgumentException thrown by Email.valueOf()
        IllegalArgumentException exception = new IllegalArgumentException("Invalid email format: not-an-email");
        WebRequest request = null;

        // Act
        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleIllegalArgumentException(exception, request);

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Invalid email format: not-an-email", response.getBody().getMessage());
    }

    /**
     * Should handle username validation error.
     */
    @Test
    void shouldHandleUsernameValidationError() {
        // Arrange - IllegalArgumentException thrown by Username.valueOf()
        IllegalArgumentException exception = new IllegalArgumentException("Username must be at least 3 characters long");
        WebRequest request = null;

        // Act
        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleIllegalArgumentException(exception, request);

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Username must be at least 3 characters long", response.getBody().getMessage());
    }

    /**
     * Should handle password validation error.
     */
    @Test
    void shouldHandlePasswordValidationError() {
        // Arrange - IllegalArgumentException thrown by Password.valueOf()
        IllegalArgumentException exception = new IllegalArgumentException("Password must be at least 6 characters long");
        WebRequest request = null;

        // Act
        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleIllegalArgumentException(exception, request);

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Password must be at least 6 characters long", response.getBody().getMessage());
    }

    // ========== AUTHENTICATION MESSAGE FORMAT TESTS ==========

    /**
     * Should format authentication error messages.
     */
    @Test
    void shouldFormatAuthenticationErrorMessages() {
        // Arrange
        AuthenticationException exception = new BadCredentialsException("Bad credentials");
        WebRequest request = null;

        // Act
        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleAuthenticationException(exception, request);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Authentication Failed: Bad credentials", response.getBody().getMessage());
    }

    /**
     * Should use fixed access denied message.
     */
    @Test
    void shouldUseFixedAccessDeniedMessage() {
        // Arrange
        AccessDeniedException exception = new AccessDeniedException("Some specific access denied reason");
        WebRequest request = null;

        // Act
        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleAccessDeniedException(exception, request);

        // Assert
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertNotNull(response.getBody());
        // Should use fixed message, not the exception message
        assertEquals("Access Denied: You do not have permission to perform this action.", response.getBody().getMessage());
    }
}
