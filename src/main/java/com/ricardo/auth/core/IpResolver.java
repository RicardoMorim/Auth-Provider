package com.ricardo.auth.core;

import jakarta.servlet.http.HttpServletRequest;

/**
 * The interface Ip resolver.
 */
public interface IpResolver {
    /**
     * Resolve ip string.
     *
     * @param request the request
     * @return the string
     */
    String resolveIp(HttpServletRequest request);
}
