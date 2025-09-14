package com.ricardo.auth.service;

import com.ricardo.auth.core.IpResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.stereotype.Service;

public class SimpleIpResolver implements IpResolver {
    @Override
    public String resolveIp(HttpServletRequest request) {
        return request.getRemoteAddr();
    }
}
