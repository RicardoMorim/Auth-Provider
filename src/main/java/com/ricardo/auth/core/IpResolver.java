package com.ricardo.auth.core;

import jakarta.servlet.http.HttpServletRequest;

import java.net.http.HttpRequest;

public interface IpResolver {
    String resolveIp(HttpServletRequest request);
}
