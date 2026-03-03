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
}
