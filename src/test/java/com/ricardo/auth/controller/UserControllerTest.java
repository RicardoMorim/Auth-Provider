package com.ricardo.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.User;
import com.ricardo.auth.domain.exceptions.DuplicateResourceException;
import com.ricardo.auth.dto.CreateUserRequestDTO;
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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UserController.class)
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private UserService<User, Long> userService;

    @MockBean
    private PasswordEncoder passwordEncoder;

    // Este mock é crucial porque a SecurityConfig é carregada e depende dele.
    @MockBean
    private JwtService jwtService;

    @Test
    void createUser_shouldReturn201_whenRequestIsValid() throws Exception {
        // Arrange
        CreateUserRequestDTO request = new CreateUserRequestDTO("newUser", "new@example.com", "password123");

        // Simular o objeto User que o serviço retornaria
        User mockUser = org.mockito.Mockito.mock(User.class);
        when(mockUser.getId()).thenReturn(1L);
        when(mockUser.getUsername()).thenReturn(request.getUsername());
        when(mockUser.getEmail()).thenReturn(request.getEmail());

        when(userService.createUser(any(User.class))).thenReturn(mockUser);

        // Act & Assert
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value("1"))
                .andExpect(jsonPath("$.username").value(request.getUsername()))
                .andExpect(jsonPath("$.email").value(request.getEmail()));
    }

    @Test
    void createUser_shouldReturn409_whenEmailAlreadyExists() throws Exception {
        // Arrange
        CreateUserRequestDTO request = new CreateUserRequestDTO("existingUser", "existing@example.com", "password123");
        String errorMessage = "Email already exists: " + request.getEmail();

        // Configurar o mock do serviço para lançar a exceção esperada.
        // O GlobalExceptionHandler irá capturar isto e retornar um 409 Conflict.
        when(userService.createUser(any(User.class)))
                .thenThrow(new DuplicateResourceException(errorMessage));

        // Act & Assert
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value(errorMessage));
    }
}