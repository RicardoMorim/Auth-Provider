package com.ricardo.auth.security;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.TokenBlocklist;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class JwtAuthFilterUnitTest {

    private JwtService jwtService;
    private TokenBlocklist tokenBlocklist;
    private JwtAuthFilter jwtAuthFilter;

    @BeforeEach
    void setUp() {
        jwtService = mock(JwtService.class);
        tokenBlocklist = mock(TokenBlocklist.class);

        AuthProperties authProperties = new AuthProperties();
        authProperties.getCookies().getAccess().setSecure(true);
        authProperties.getCookies().getAccess().setPath("/");

        jwtAuthFilter = new JwtAuthFilter(jwtService, tokenBlocklist, authProperties);
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterInternal_WhenSecureCookieRequiredAndRequestInsecure_ShouldReturnUnauthorized() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/protected");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        request.setSecure(false);
        request.setCookies(new Cookie("access_token", "aaa.bbb.ccc"));

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(401);
        verify(filterChain, never()).doFilter(any(), any());
        verifyNoInteractions(jwtService);
    }

    @Test
    void doFilterInternal_WhenForwardedProtoIsHttps_ShouldAllowValidationFlow() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/protected");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        request.setSecure(false);
        request.addHeader("X-Forwarded-Proto", "https");
        request.setCookies(new Cookie("access_token", "aaa.bbb.ccc"));

        when(tokenBlocklist.isRevoked("aaa.bbb.ccc")).thenReturn(false);
        when(jwtService.isTokenValid("aaa.bbb.ccc")).thenReturn(true);
        when(jwtService.extractSubject("aaa.bbb.ccc")).thenReturn("user@example.com");
        when(jwtService.extractRoles("aaa.bbb.ccc")).thenReturn(List.of("ROLE_USER"));

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertThat(response.getStatus()).isNotEqualTo(401);
        verify(filterChain).doFilter(any(), any());
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    }

    @Test
    void doFilterInternal_WhenSubjectIsBlank_ShouldReturnUnauthorized() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/protected");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        request.setSecure(true);
        request.setCookies(new Cookie("access_token", "aaa.bbb.ccc"));

        when(tokenBlocklist.isRevoked("aaa.bbb.ccc")).thenReturn(false);
        when(jwtService.isTokenValid("aaa.bbb.ccc")).thenReturn(true);
        when(jwtService.extractSubject("aaa.bbb.ccc")).thenReturn("   ");
        when(jwtService.extractRoles("aaa.bbb.ccc")).thenReturn(List.of("ROLE_USER"));

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(401);
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void doFilterInternal_WhenRolesAreNull_ShouldReturnUnauthorized() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/protected");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        request.setSecure(true);
        request.setCookies(new Cookie("access_token", "aaa.bbb.ccc"));

        when(tokenBlocklist.isRevoked("aaa.bbb.ccc")).thenReturn(false);
        when(jwtService.isTokenValid("aaa.bbb.ccc")).thenReturn(true);
        when(jwtService.extractSubject("aaa.bbb.ccc")).thenReturn("user@example.com");
        when(jwtService.extractRoles("aaa.bbb.ccc")).thenReturn(null);

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(401);
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void doFilterInternal_WhenPublicEndpoint_ShouldBypassAuthentication() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(any(), any());
        verifyNoInteractions(jwtService, tokenBlocklist);
    }
}
