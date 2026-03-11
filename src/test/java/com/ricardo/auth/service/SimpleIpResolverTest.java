package com.ricardo.auth.service;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SimpleIpResolverTest {

    private final SimpleIpResolver resolver = new SimpleIpResolver();

    @Test
    void resolveIp_shouldReturnRemoteAddress() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("192.168.1.10");

        String result = resolver.resolveIp(request);

        assertEquals("192.168.1.10", result);
    }

    @Test
    void resolveIp_shouldIgnoreForwardedHeadersByDefault() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("X-Forwarded-For")).thenReturn("10.0.0.5");
        when(request.getHeader("X-Real-IP")).thenReturn("10.0.0.6");
        when(request.getRemoteAddr()).thenReturn("192.168.1.10");

        String result = resolver.resolveIp(request);

        assertEquals("192.168.1.10", result);
    }
}
