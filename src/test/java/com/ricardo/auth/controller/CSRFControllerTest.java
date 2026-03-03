package com.ricardo.auth.controller;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CSRFControllerTest {

    private final CSRFController csrfController = new CSRFController();

    @Test
    void getCsrfToken_WhenTokenAlreadyPresent_ShouldReturnExistingTokenInfo() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/csrf-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CsrfToken existingToken = new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", "abc123token");
        request.setAttribute(CsrfToken.class.getName(), existingToken);

        ResponseEntity<Map<String, String>> result = csrfController.getCsrfToken(request, response);

        assertThat(result.getStatusCode().value()).isEqualTo(200);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody()).containsEntry("token", "abc123token");
        assertThat(result.getBody()).containsEntry("headerName", "X-XSRF-TOKEN");
        assertThat(result.getBody()).containsEntry("parameterName", "_csrf");
    }

    @Test
    void getCsrfToken_WhenTokenMissing_ShouldGenerateAndPersistToken() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/csrf-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        ResponseEntity<Map<String, String>> result = csrfController.getCsrfToken(request, response);

        assertThat(result.getStatusCode().value()).isEqualTo(200);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody()).containsKeys("token", "headerName", "parameterName");
        assertThat(result.getBody().get("token")).isNotBlank();
        assertThat(result.getBody().get("headerName")).isEqualTo("X-XSRF-TOKEN");
        assertThat(result.getBody().get("parameterName")).isEqualTo("_csrf");
        assertThat(response.getCookie("XSRF-TOKEN")).isNotNull();
    }
}
