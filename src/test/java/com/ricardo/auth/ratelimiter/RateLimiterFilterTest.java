package com.ricardo.auth.ratelimiter;

import com.ricardo.auth.core.IpResolver;
import com.ricardo.auth.core.RateLimiter;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class RateLimiterFilterTest {

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterInternal_shouldBypassRateLimiting_whenDisabled() throws ServletException, IOException {
        RateLimiter rateLimiter = mock(RateLimiter.class);
        IpResolver ipResolver = mock(IpResolver.class);
        when(rateLimiter.isEnabled()).thenReturn(false);

        RateLimiterFilter filter = new RateLimiterFilter(rateLimiter, ipResolver);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        verify(rateLimiter, never()).allowRequest(anyString());
        assertEquals(200, response.getStatus());
    }

    @Test
    void doFilterInternal_shouldReturn429_whenRequestDenied() throws ServletException, IOException {
        RateLimiter rateLimiter = mock(RateLimiter.class);
        IpResolver ipResolver = mock(IpResolver.class);
        when(rateLimiter.isEnabled()).thenReturn(true);
        when(ipResolver.resolveIp(any())).thenReturn("10.0.0.1");
        when(rateLimiter.allowRequest("10.0.0.1")).thenReturn(false);

        RateLimiterFilter filter = new RateLimiterFilter(rateLimiter, ipResolver);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        assertEquals(429, response.getStatus());
        assertEquals("Rate limit exceeded", response.getErrorMessage());
    }

    @Test
    void doFilterInternal_shouldUseAuthenticatedPrincipalName_whenAvailable() throws ServletException, IOException {
        RateLimiter rateLimiter = mock(RateLimiter.class);
        IpResolver ipResolver = mock(IpResolver.class);
        when(rateLimiter.isEnabled()).thenReturn(true);
        when(rateLimiter.allowRequest("alice@example.com")).thenReturn(true);

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("alice@example.com", "password", Collections.emptyList())
        );

        RateLimiterFilter filter = new RateLimiterFilter(rateLimiter, ipResolver);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        verify(rateLimiter).allowRequest("alice@example.com");
        verify(ipResolver, never()).resolveIp(any());
        assertEquals(200, response.getStatus());
    }

    @Test
    void doFilterInternal_shouldFallbackToIp_whenNoAuthentication() throws ServletException, IOException {
        RateLimiter rateLimiter = mock(RateLimiter.class);
        IpResolver ipResolver = mock(IpResolver.class);
        when(rateLimiter.isEnabled()).thenReturn(true);
        when(ipResolver.resolveIp(any())).thenReturn("127.0.0.1");
        when(rateLimiter.allowRequest("127.0.0.1")).thenReturn(true);

        RateLimiterFilter filter = new RateLimiterFilter(rateLimiter, ipResolver);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        verify(rateLimiter).allowRequest("127.0.0.1");
        verify(ipResolver).resolveIp(request);
        assertEquals(200, response.getStatus());
    }
}
