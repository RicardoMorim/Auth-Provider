package com.ricardo.auth.service;

import com.ricardo.auth.core.IpResolver;
import jakarta.servlet.http.HttpServletRequest;

/**
 * The type Simple ip resolver.
 */
public class SimpleIpResolver implements IpResolver {
    @Override
    public String resolveIp(HttpServletRequest request) {
        return request.getRemoteAddr();
    }
}
