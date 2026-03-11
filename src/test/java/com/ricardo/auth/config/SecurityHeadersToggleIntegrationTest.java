package com.ricardo.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "ricardo.auth.security-headers.csp.enabled=false",
        "ricardo.auth.security-headers.hsts.enabled=false"
})
class SecurityHeadersToggleIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void csrfTokenEndpoint_shouldNotIncludeCspOrHsts_whenDisabled() throws Exception {
        mockMvc.perform(get("/api/csrf-token").secure(true))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("Content-Security-Policy"))
                .andExpect(header().doesNotExist("Strict-Transport-Security"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"));
    }
}
