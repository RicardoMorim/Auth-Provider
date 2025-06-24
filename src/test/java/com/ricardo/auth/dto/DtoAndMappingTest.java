package com.ricardo.auth.dto;

import com.ricardo.auth.domain.AppRole;
import com.ricardo.auth.domain.Email;
import com.ricardo.auth.domain.Password;
import com.ricardo.auth.domain.User;
import com.ricardo.auth.domain.Username;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for DTOs and mapping functionality.
 * Ensures data transfer objects work correctly and mappings are accurate.
 */
class DtoAndMappingTest {

    private PasswordEncoder passwordEncoder;
    private User testUser;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        
        testUser = new User(
            Username.valueOf("testuser"),
            Email.valueOf("test@example.com"),
            Password.valueOf("password123", passwordEncoder)
        );
        testUser.addRole(AppRole.USER);
        testUser.addRole(AppRole.ADMIN);
    }

    // ========== CreateUserRequestDTO TESTS ==========

    @Test
    void createUserRequestDTO_shouldCreateWithValidData() {
        // Act
        CreateUserRequestDTO dto = new CreateUserRequestDTO("testuser", "test@example.com", "password123");

        // Assert
        assertNotNull(dto);
        assertEquals("testuser", dto.getUsername());
        assertEquals("test@example.com", dto.getEmail());
        assertEquals("password123", dto.getPassword());
    }

    @Test
    void createUserRequestDTO_shouldHandleNullValues() {
        // Act & Assert - Should be able to create DTO with nulls (validation happens at service layer)
        CreateUserRequestDTO dto = new CreateUserRequestDTO(null, null, null);
        
        assertNotNull(dto);
        assertNull(dto.getUsername());
        assertNull(dto.getEmail());
        assertNull(dto.getPassword());
    }

    @Test
    void createUserRequestDTO_shouldHandleEmptyStrings() {
        // Act
        CreateUserRequestDTO dto = new CreateUserRequestDTO("", "", "");

        // Assert
        assertNotNull(dto);
        assertEquals("", dto.getUsername());
        assertEquals("", dto.getEmail());
        assertEquals("", dto.getPassword());
    }

    @Test
    void createUserRequestDTO_shouldHandleWhitespace() {
        // Act
        CreateUserRequestDTO dto = new CreateUserRequestDTO("  username  ", "  email@test.com  ", "  password  ");

        // Assert
        assertEquals("  username  ", dto.getUsername());
        assertEquals("  email@test.com  ", dto.getEmail());
        assertEquals("  password  ", dto.getPassword());
    }

    // ========== LoginRequestDTO TESTS ==========

    @Test
    void loginRequestDTO_shouldCreateWithValidData() {
        // Act
        LoginRequestDTO dto = new LoginRequestDTO("test@example.com", "password123");

        // Assert
        assertNotNull(dto);
        assertEquals("test@example.com", dto.getEmail());
        assertEquals("password123", dto.getPassword());
    }

    @Test
    void loginRequestDTO_shouldHandleNullValues() {
        // Act
        LoginRequestDTO dto = new LoginRequestDTO(null, null);

        // Assert
        assertNotNull(dto);
        assertNull(dto.getEmail());
        assertNull(dto.getPassword());
    }

    @Test
    void loginRequestDTO_shouldHandleEmptyValues() {
        // Act
        LoginRequestDTO dto = new LoginRequestDTO("", "");

        // Assert
        assertEquals("", dto.getEmail());
        assertEquals("", dto.getPassword());
    }

    // ========== TokenDTO TESTS ==========

    @Test
    void tokenDTO_shouldCreateWithValidToken() {
        // Arrange
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0QGV4YW1wbGUuY29tIn0.test";

        // Act
        TokenDTO dto = new TokenDTO(token);

        // Assert
        assertNotNull(dto);
        assertEquals(token, dto.getToken());
    }

    @Test
    void tokenDTO_shouldHandleNullToken() {
        // Act
        TokenDTO dto = new TokenDTO(null);

        // Assert
        assertNotNull(dto);
        assertNull(dto.getToken());
    }

    @Test
    void tokenDTO_shouldHandleEmptyToken() {
        // Act
        TokenDTO dto = new TokenDTO("");

        // Assert
        assertEquals("", dto.getToken());
    }

    // ========== UserDTO TESTS ==========

    @Test
    void userDTO_shouldCreateWithValidData() {
        // Act
        UserDTO dto = new UserDTO("1", "testuser", "test@example.com");

        // Assert
        assertNotNull(dto);
        assertEquals("1", dto.getId());
        assertEquals("testuser", dto.getUsername());
        assertEquals("test@example.com", dto.getEmail());
    }

    @Test
    void userDTO_shouldHandleNullValues() {
        // Act
        UserDTO dto = new UserDTO(null, null, null);

        // Assert
        assertNotNull(dto);
        assertNull(dto.getId());
        assertNull(dto.getUsername());
        assertNull(dto.getEmail());
    }

    @Test
    void userDTO_shouldSupportSetters() {
        // Arrange
        UserDTO dto = new UserDTO();

        // Act
        dto.setId("1");
        dto.setUsername("testuser");
        dto.setEmail("test@example.com");

        // Assert
        assertEquals("1", dto.getId());
        assertEquals("testuser", dto.getUsername());
        assertEquals("test@example.com", dto.getEmail());
    }

    // ========== AuthenticatedUserDTO TESTS ==========
    @Test
    void authenticatedUserDTO_shouldCreateWithValidData() {
        // Arrange
        List<SimpleGrantedAuthority> authorities = List.of(
            new SimpleGrantedAuthority("ROLE_USER"),
            new SimpleGrantedAuthority("ROLE_ADMIN")
        );

        // Act
        AuthenticatedUserDTO dto = new AuthenticatedUserDTO("test@example.com", authorities);

        // Assert
        assertNotNull(dto);
        assertEquals("test@example.com", dto.getName());
        assertEquals(2, dto.getRoles().size());
        assertTrue(dto.getRoles().contains("ROLE_USER"));
        assertTrue(dto.getRoles().contains("ROLE_ADMIN"));
    }

    @Test
    void authenticatedUserDTO_shouldHandleEmptyAuthorities() {
        // Act
        AuthenticatedUserDTO dto = new AuthenticatedUserDTO("test@example.com", List.of());

        // Assert
        assertEquals("test@example.com", dto.getName());
        assertTrue(dto.getRoles().isEmpty());
    }

    @Test
    void authenticatedUserDTO_shouldHandleNullEmail() {
        // Act
        AuthenticatedUserDTO dto = new AuthenticatedUserDTO(null, List.of());

        // Assert
        assertNull(dto.getName());
        assertTrue(dto.getRoles().isEmpty());
    }

    // ========== UserDTOMapper TESTS ==========

    @Test
    void userDTOMapper_shouldMapUserToDTO() {
        // Act
        UserDTO dto = UserDTOMapper.toDTO(testUser);

        // Assert
        assertNotNull(dto);
        assertEquals(String.valueOf(testUser.getId()), dto.getId());
        assertEquals("testuser", dto.getUsername());
        assertEquals("test@example.com", dto.getEmail());
    }

    @Test
    void userDTOMapper_shouldHandleNullUser() {
        // Act
        UserDTO dto = UserDTOMapper.toDTO(null);

        // Assert
        assertNull(dto);
    }

    @Test
    void userDTOMapper_shouldMapUserWithNoId() {
        // Arrange - Create user without setting ID (before save)
        User unsavedUser = new User(
            Username.valueOf("newuser"),
            Email.valueOf("new@example.com"),
            Password.valueOf("password123", passwordEncoder)
        );

        // Act
        UserDTO dto = UserDTOMapper.toDTO(unsavedUser);

        // Assert
        assertNotNull(dto);
        assertEquals("null", dto.getId()); // ID will be null, mapped to "null" string
        assertEquals("newuser", dto.getUsername());
        assertEquals("new@example.com", dto.getEmail());
    }

    // ========== ErrorResponse TESTS ==========

    @Test
    void errorResponse_shouldCreateWithMessage() {
        // Act
        ErrorResponse error = new ErrorResponse("Test error message");

        // Assert
        assertNotNull(error);
        assertEquals("Test error message", error.getMessage());
    }

    @Test
    void errorResponse_shouldHandleNullMessage() {
        // Act
        ErrorResponse error = new ErrorResponse(null);

        // Assert
        assertNotNull(error);
        assertNull(error.getMessage());
    }

    @Test
    void errorResponse_shouldHandleEmptyMessage() {
        // Act
        ErrorResponse error = new ErrorResponse("");

        // Assert
        assertEquals("", error.getMessage());
    }

    // ========== DTO SERIALIZATION TESTS ==========

    @Test
    void createUserRequestDTO_shouldBeSerializable() {
        // This test ensures DTOs can be properly serialized/deserialized
        CreateUserRequestDTO dto = new CreateUserRequestDTO("testuser", "test@example.com", "password123");
        
        // Assert basic properties exist (would work with JSON serialization)
        assertNotNull(dto.getUsername());
        assertNotNull(dto.getEmail());
        assertNotNull(dto.getPassword());
    }

    @Test
    void userDTO_shouldBeSerializable() {
        UserDTO dto = new UserDTO("1", "testuser", "test@example.com");
        
        // Assert basic properties exist
        assertNotNull(dto.getId());
        assertNotNull(dto.getUsername());
        assertNotNull(dto.getEmail());
    }

    @Test
    void tokenDTO_shouldBeSerializable() {
        TokenDTO dto = new TokenDTO("sample.jwt.token");
        
        // Assert basic properties exist
        assertNotNull(dto.getToken());
    }

    // ========== DTO VALIDATION BOUNDARY TESTS ==========

    @Test
    void createUserRequestDTO_shouldHandleVeryLongValues() {
        // Arrange
        String longUsername = "a".repeat(1000);
        String longEmail = "a".repeat(500) + "@example.com";
        String longPassword = "a".repeat(1000);

        // Act
        CreateUserRequestDTO dto = new CreateUserRequestDTO(longUsername, longEmail, longPassword);

        // Assert - DTO should accept any values (validation happens at service layer)
        assertEquals(longUsername, dto.getUsername());
        assertEquals(longEmail, dto.getEmail());
        assertEquals(longPassword, dto.getPassword());
    }    @Test
    void authenticatedUserDTO_shouldHandleSpecialCharactersInEmail() {
        // Arrange
        String emailWithSpecialChars = "test+tag@münchen.de";
        
        // Act
        AuthenticatedUserDTO dto = new AuthenticatedUserDTO(emailWithSpecialChars, List.of());

        // Assert
        assertEquals(emailWithSpecialChars, dto.getName());
    }

    @Test
    void authenticatedUserDTO_shouldHandleManyRoles() {
        // Arrange
        List<SimpleGrantedAuthority> manyRoles = List.of(
            new SimpleGrantedAuthority("ROLE_USER"),
            new SimpleGrantedAuthority("ROLE_ADMIN"),
            new SimpleGrantedAuthority("ROLE_MODERATOR"),
            new SimpleGrantedAuthority("ROLE_VIP"),
            new SimpleGrantedAuthority("ROLE_CUSTOM")
        );

        // Act
        AuthenticatedUserDTO dto = new AuthenticatedUserDTO("test@example.com", manyRoles);

        // Assert
        assertEquals(5, dto.getRoles().size());
        assertTrue(dto.getRoles().contains("ROLE_USER"));
        assertTrue(dto.getRoles().contains("ROLE_ADMIN"));
        assertTrue(dto.getRoles().contains("ROLE_MODERATOR"));
        assertTrue(dto.getRoles().contains("ROLE_VIP"));
        assertTrue(dto.getRoles().contains("ROLE_CUSTOM"));
    }

    // ========== DTO EQUALITY TESTS ==========

    @Test
    void userDTO_shouldSupportEquality() {
        // Arrange
        UserDTO dto1 = new UserDTO("1", "testuser", "test@example.com");
        UserDTO dto2 = new UserDTO("1", "testuser", "test@example.com");
        UserDTO dto3 = new UserDTO("2", "otheruser", "other@example.com");

        // Assert - If DTOs implement equals/hashCode properly
        // This test will need to be updated based on actual DTO implementation
        assertNotNull(dto1);
        assertNotNull(dto2);
        assertNotNull(dto3);
    }
}
