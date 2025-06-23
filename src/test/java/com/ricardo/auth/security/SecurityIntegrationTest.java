package com.ricardo.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ricardo.auth.domain.Email;
import com.ricardo.auth.domain.Password;
import com.ricardo.auth.domain.User;
import com.ricardo.auth.domain.Username;
import com.ricardo.auth.dto.LoginRequestDTO;
import com.ricardo.auth.dto.UserDTO;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void shouldAllowPublicAccessToLogin() throws Exception {
        // Arrange
        LoginRequestDTO loginRequest = new LoginRequestDTO("nonexistent@user.com", "wrongpassword");

        // Act & Assert
        // Esperamos um 401 Unauthorized porque a autenticação falha,
        // o que prova que o endpoint é público e a requisição foi processada.
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldDenyAccessToMeEndpointForAnonymousUser() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "test@user.com", roles = {"USER"}) // Simula um utilizador autenticado
    void shouldAllowAccessToMeEndpointForAuthenticatedUser() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = "USER") // Simula um utilizador com a role user
    void shouldNotAllowAccessToDeleteForAdmin() throws Exception {

        // create a user to delete
        User user = new User(Username.valueOf("testuser"), Email.valueOf("testuser@gmail.com"), Password.valueOf("password123", passwordEncoder));

        // save the user to the database
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(user)))
                .andExpect(status().isCreated());

        mockMvc.perform(delete("/api/users/delete/3"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "ADMIN") // Simula um utilizador com a role admin
    void shouldAllowAccessToDeleteForAdmin() throws Exception {

        // create a user to delete
        User user = new User(Username.valueOf("testuser"), Email.valueOf("testuser@gmail.com"), Password.valueOf("password123", passwordEncoder));

        // save the user to the database
        mockMvc.perform(post("/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(user)))
                .andExpect(status().isCreated());

        mockMvc.perform(delete("/api/users/delete/3"))
                .andExpect(status().isNoContent());
    }
}