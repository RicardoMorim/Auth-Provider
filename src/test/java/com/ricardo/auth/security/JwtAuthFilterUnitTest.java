package com.ricardo.auth.security;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.TokenBlocklist;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class JwtAuthFilterUnitTest {

    private static final String TOKEN = "aaa.bbb.ccc";

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterInternal_shouldBypassPublicEndpoint() throws ServletException, IOException {
        JwtService jwtService = mock(JwtService.class);
        TokenBlocklist tokenBlocklist = mock(TokenBlocklist.class);
        JwtAuthFilter filter = newFilter(jwtService, tokenBlocklist, false, "/");

        MockHttpServletRequest request = request("/api/auth/login", null);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
        verifyNoInteractions(jwtService, tokenBlocklist);
    }

    @Test
    void doFilterInternal_shouldReturn401_whenCookieMissing() throws ServletException, IOException {
        JwtAuthFilter filter = newFilter(mock(JwtService.class), mock(TokenBlocklist.class), false, "/");

        MockHttpServletResponse response = runFilter(filter, request("/api/private", null));

        assertEquals(401, response.getStatus());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void doFilterInternal_shouldReturn401_whenSecureCookieExpectedOnInsecureRequest() throws ServletException, IOException {
        JwtAuthFilter filter = newFilter(mock(JwtService.class), mock(TokenBlocklist.class), true, "/");

        MockHttpServletRequest request = request("/api/private", TOKEN);
        request.setSecure(false);
        MockHttpServletResponse response = runFilter(filter, request);

        assertEquals(401, response.getStatus());
    }

    @Test
    void doFilterInternal_shouldContinue_whenForwardedProtoIsHttps() throws ServletException, IOException {
        JwtService jwtService = mock(JwtService.class);
        TokenBlocklist tokenBlocklist = mock(TokenBlocklist.class);
        when(tokenBlocklist.isRevoked(TOKEN)).thenReturn(false);
        when(jwtService.isTokenValid(TOKEN)).thenReturn(true);
        when(jwtService.extractSubject(TOKEN)).thenReturn("user@example.com");
        when(jwtService.extractRoles(TOKEN)).thenReturn(List.of("ROLE_USER"));
        JwtAuthFilter filter = newFilter(jwtService, tokenBlocklist, true, "/");

        MockHttpServletRequest request = request("/api/private", TOKEN);
        request.setSecure(false);
        request.addHeader("X-Forwarded-Proto", "https");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
        assertEquals(200, response.getStatus());
    }

    @Test
    void doFilterInternal_shouldReturn401_whenCookiePathMismatch() throws ServletException, IOException {
        JwtAuthFilter filter = newFilter(mock(JwtService.class), mock(TokenBlocklist.class), false, "/api/auth");

        MockHttpServletResponse response = runFilter(filter, request("/api/private", TOKEN));

        assertEquals(401, response.getStatus());
    }

    @Test
    void doFilterInternal_shouldReturn401_whenTokenFormatInvalid() throws ServletException, IOException {
        JwtService jwtService = mock(JwtService.class);
        TokenBlocklist tokenBlocklist = mock(TokenBlocklist.class);
        JwtAuthFilter filter = newFilter(jwtService, tokenBlocklist, false, "/");

        MockHttpServletResponse response = runFilter(filter, request("/api/private", "invalid-token"));

        assertEquals(401, response.getStatus());
        verifyNoInteractions(jwtService, tokenBlocklist);
    }

    @Test
    void doFilterInternal_shouldReturn401_whenTokenRevoked() throws ServletException, IOException {
        JwtService jwtService = mock(JwtService.class);
        TokenBlocklist tokenBlocklist = mock(TokenBlocklist.class);
        when(tokenBlocklist.isRevoked(TOKEN)).thenReturn(true);
        JwtAuthFilter filter = newFilter(jwtService, tokenBlocklist, false, "/");

        MockHttpServletResponse response = runFilter(filter, request("/api/private", TOKEN));

        assertEquals(401, response.getStatus());
        verify(tokenBlocklist).isRevoked(TOKEN);
        verifyNoInteractions(jwtService);
    }

    @Test
    void doFilterInternal_shouldReturn401_whenJwtServiceSaysInvalid() throws ServletException, IOException {
        JwtService jwtService = mock(JwtService.class);
        TokenBlocklist tokenBlocklist = mock(TokenBlocklist.class);
        when(tokenBlocklist.isRevoked(TOKEN)).thenReturn(false);
        when(jwtService.isTokenValid(TOKEN)).thenReturn(false);
        JwtAuthFilter filter = newFilter(jwtService, tokenBlocklist, false, "/");

        MockHttpServletResponse response = runFilter(filter, request("/api/private", TOKEN));

        assertEquals(401, response.getStatus());
    }

    @Test
    void doFilterInternal_shouldReturn401_whenJwtParsingThrowsMalformed() throws ServletException, IOException {
        JwtService jwtService = mock(JwtService.class);
        TokenBlocklist tokenBlocklist = mock(TokenBlocklist.class);
        when(tokenBlocklist.isRevoked(TOKEN)).thenReturn(false);
        when(jwtService.isTokenValid(TOKEN)).thenThrow(new MalformedJwtException("bad token"));
        JwtAuthFilter filter = newFilter(jwtService, tokenBlocklist, false, "/");

        MockHttpServletResponse response = runFilter(filter, request("/api/private", TOKEN));

        assertEquals(401, response.getStatus());
    }

    @Test
    void doFilterInternal_shouldReturn401_whenSubjectMissing() throws ServletException, IOException {
        JwtService jwtService = mock(JwtService.class);
        TokenBlocklist tokenBlocklist = mock(TokenBlocklist.class);
        when(tokenBlocklist.isRevoked(TOKEN)).thenReturn(false);
        when(jwtService.isTokenValid(TOKEN)).thenReturn(true);
        when(jwtService.extractSubject(TOKEN)).thenReturn("  ");
        when(jwtService.extractRoles(TOKEN)).thenReturn(List.of("ROLE_USER"));
        JwtAuthFilter filter = newFilter(jwtService, tokenBlocklist, false, "/");

        MockHttpServletResponse response = runFilter(filter, request("/api/private", TOKEN));

        assertEquals(401, response.getStatus());
    }

    @Test
    void doFilterInternal_shouldReturn401_whenRolesMissing() throws ServletException, IOException {
        JwtService jwtService = mock(JwtService.class);
        TokenBlocklist tokenBlocklist = mock(TokenBlocklist.class);
        when(tokenBlocklist.isRevoked(TOKEN)).thenReturn(false);
        when(jwtService.isTokenValid(TOKEN)).thenReturn(true);
        when(jwtService.extractSubject(TOKEN)).thenReturn("user@example.com");
        when(jwtService.extractRoles(TOKEN)).thenReturn(null);
        JwtAuthFilter filter = newFilter(jwtService, tokenBlocklist, false, "/");

        MockHttpServletResponse response = runFilter(filter, request("/api/private", TOKEN));

        assertEquals(401, response.getStatus());
    }

    @Test
    void doFilterInternal_shouldAuthenticateAndContinue_whenTokenValid() throws ServletException, IOException {
        JwtService jwtService = mock(JwtService.class);
        TokenBlocklist tokenBlocklist = mock(TokenBlocklist.class);
        when(tokenBlocklist.isRevoked(TOKEN)).thenReturn(false);
        when(jwtService.isTokenValid(TOKEN)).thenReturn(true);
        when(jwtService.extractSubject(TOKEN)).thenReturn("user@example.com");
        when(jwtService.extractRoles(TOKEN)).thenReturn(List.of("ROLE_USER", "ROLE_ADMIN"));
        JwtAuthFilter filter = newFilter(jwtService, tokenBlocklist, false, "/");

        MockHttpServletRequest request = request("/api/private", TOKEN);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("user@example.com", SecurityContextHolder.getContext().getAuthentication().getName());
    }

    @Test
    void doFilterInternal_shouldNotOverrideExistingAuthentication() throws ServletException, IOException {
        JwtService jwtService = mock(JwtService.class);
        TokenBlocklist tokenBlocklist = mock(TokenBlocklist.class);
        when(tokenBlocklist.isRevoked(TOKEN)).thenReturn(false);
        when(jwtService.isTokenValid(TOKEN)).thenReturn(true);
        when(jwtService.extractSubject(TOKEN)).thenReturn("new@example.com");
        when(jwtService.extractRoles(TOKEN)).thenReturn(List.of("ROLE_USER"));
        JwtAuthFilter filter = newFilter(jwtService, tokenBlocklist, false, "/");

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("existing@example.com", null, List.of())
        );

        MockHttpServletRequest request = request("/api/private", TOKEN);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
        assertEquals("existing@example.com", SecurityContextHolder.getContext().getAuthentication().getName());
    }

    private JwtAuthFilter newFilter(JwtService jwtService, TokenBlocklist tokenBlocklist, boolean secureCookie, String path) {
        AuthProperties properties = new AuthProperties();
        properties.getCookies().getAccess().setSecure(secureCookie);
        properties.getCookies().getAccess().setPath(path);
        return new JwtAuthFilter(jwtService, tokenBlocklist, properties);
    }

    private MockHttpServletRequest request(String uri, String token) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(uri);
        if (token != null) {
            request.setCookies(new Cookie("access_token", token));
        }
        return request;
    }

    private MockHttpServletResponse runFilter(JwtAuthFilter filter, MockHttpServletRequest request)
            throws ServletException, IOException {
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);
        filter.doFilterInternal(request, response, chain);
        verify(chain, never()).doFilter(any(), any());
        return response;
    }
}
