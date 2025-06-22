import com.ricardo.auth.domain.User;
import com.ricardo.auth.repository.UserRepositoryTest;
import com.ricardo.auth.service.UserServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    private UserRepositoryTest<User, Long> userRepository;

    @InjectMocks
    private UserServiceImpl<User, Long> userService;

    @Test
    void createUser_shouldThrowException_whenEmailExists() {
        // Arrange
        User user = mock(User.class);
        when(user.getEmail()).thenReturn("test@example.com");
        when(userRepository.existsByEmail("test@example.com")).thenReturn(true);

        // Act & Assert
        Exception exception = assertThrows(RuntimeException.class, () -> {
            userService.createUser(user);
        });
        assertEquals("Email already exists: test@example.com", exception.getMessage());

        // Verify
        verify(userRepository, never()).save(any());
    }
}