package com.ricardo.auth.controller;

import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.UserService;
import com.ricardo.auth.domain.user.AppRole;
import com.ricardo.auth.domain.user.User;
import com.ricardo.auth.factory.AuthUserFactory;
import com.ricardo.auth.helper.IdConverter;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.UUID;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class UserControllerValidationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtService jwtService;

    @MockBean
    private UserService<User, AppRole, UUID> userService;

    @MockBean
    private AuthUserFactory<User, AppRole, UUID> userBuilder;

    @MockBean
    private IdConverter<UUID> idConverter;

    @Test
    void getUserByEmail_shouldReturn400_whenEmailPathVariableIsInvalid() throws Exception {
        String token = adminToken();

        mockMvc.perform(get("/api/users/email/not-an-email")
                .cookie(new Cookie("access_token", token)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());

        verify(userService, never()).getUserByEmail(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void userExists_shouldReturn400_whenEmailPathVariableIsInvalid() throws Exception {
        String token = adminToken();

        mockMvc.perform(get("/api/users/exists/not-an-email")
                .cookie(new Cookie("access_token", token)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());

        verify(userService, never()).userExists(org.mockito.ArgumentMatchers.anyString());
    }

    private String adminToken() {
        return jwtService.generateAccessToken(
                "admin@example.com",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
    }
}
