import com.fasterxml.jackson.databind.ObjectMapper;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.User;
import com.ricardo.auth.dto.CreateUserRequestDTO;
import com.ricardo.auth.dto.UserDTO;
import com.ricardo.auth.dto.UserDTOMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(UserController.class)
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private UserService<User, Long> userService;

    @MockBean
    private PasswordEncoder passwordEncoder; // Também precisa ser mockado

    @Test
    void createUser_shouldReturn201_whenRequestIsValid() throws Exception {
        // Arrange
        CreateUserRequestDTO request = new CreateUserRequestDTO("testuser", "test@example.com", "password123");
        User createdUser = mock(User.class);
        when(createdUser.getId()).thenReturn(1L);
        when(createdUser.getUsername()).thenReturn("testuser");
        when(createdUser.getEmail()).thenReturn("test@example.com");

        when(userService.createUser(any(User.class))).thenReturn(createdUser);

        // Act & Assert
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value("1"))
                .andExpect(jsonPath("$.username").value("testuser"));
    }

    @Test
    void createUser_shouldReturn409_whenEmailAlreadyExists() throws Exception {
        // Arrange
        CreateUserRequestDTO request = new CreateUserRequestDTO("testuser", "test@example.com", "password123");

        when(userService.createUser(any(User.class)))
                .thenThrow(new RuntimeException("Email already exists: test@example.com"));

        // Act & Assert
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Email already exists: test@example.com"));
    }
}