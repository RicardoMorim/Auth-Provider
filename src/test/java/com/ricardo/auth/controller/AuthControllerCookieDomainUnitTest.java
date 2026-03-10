package com.ricardo.auth.controller;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.Publisher;
import com.ricardo.auth.core.RefreshTokenService;
import com.ricardo.auth.core.TokenBlocklist;
import com.ricardo.auth.core.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class AuthControllerCookieDomainUnitTest {

    @Test
    void setAccessCookie_shouldIncludeDomain_whenConfigured() {
        AuthController controller = newController(propertiesWithDomain(".example.com", null));
        MockHttpServletResponse response = new MockHttpServletResponse();

        ReflectionTestUtils.invokeMethod(controller, "setAccessCookie", response, "access-token");

        List<String> headers = response.getHeaders("Set-Cookie");
        assertTrue(headers.stream().anyMatch(h -> h.contains("access_token=") && h.contains("Domain=example.com")));
    }

    @Test
    void setRefreshCookie_shouldIncludeDomain_whenConfigured() {
        AuthController controller = newController(propertiesWithDomain(null, ".example.com"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        ReflectionTestUtils.invokeMethod(controller, "setRefreshCookie", response, "refresh-token");

        List<String> headers = response.getHeaders("Set-Cookie");
        assertTrue(headers.stream().anyMatch(h -> h.contains("refresh_token=") && h.contains("Domain=example.com")));
    }

    @Test
    void setAuthCookies_shouldNotIncludeDomain_whenUnset() {
        AuthController controller = newController(propertiesWithDomain(null, null));
        MockHttpServletResponse response = new MockHttpServletResponse();

        ReflectionTestUtils.invokeMethod(controller, "setAuthCookies", response, "access-token", "refresh-token");

        List<String> headers = response.getHeaders("Set-Cookie");
        assertFalse(headers.stream().anyMatch(h -> h.contains("Domain=")));
    }

    @Test
    void constructor_shouldRejectWildcardDomain() {
        assertThrows(IllegalArgumentException.class, () ->
                newController(propertiesWithDomain("*.example.com", null))
        );
    }

    @Test
    void constructor_shouldRejectSchemeInDomain() {
        assertThrows(IllegalArgumentException.class, () ->
                newController(propertiesWithDomain("https://example.com", null))
        );
    }

    @Test
    void constructor_shouldRejectIpAddressDomain() {
        assertThrows(IllegalArgumentException.class, () ->
                newController(propertiesWithDomain("127.0.0.1", null))
        );
    }

    @Test
    void constructor_shouldRejectLocalhostDomain() {
        assertThrows(IllegalArgumentException.class, () ->
                newController(propertiesWithDomain("localhost", null))
        );
    }

    @Test
    void constructor_shouldRejectPublicSuffixDomain() {
        assertThrows(IllegalArgumentException.class, () ->
                newController(propertiesWithDomain("co.uk", null))
        );
    }

    private AuthController newController(AuthProperties properties) {
        JwtService jwtService = mock(JwtService.class);
        AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
        RefreshTokenService refreshTokenService = mock(RefreshTokenService.class);
        TokenBlocklist tokenBlocklist = mock(TokenBlocklist.class);
        Publisher publisher = mock(Publisher.class);
        UserService userService = mock(UserService.class);

        return new AuthController<>(
                jwtService,
                authenticationManager,
                refreshTokenService,
                properties,
                tokenBlocklist,
                publisher,
                userService
        );
    }

    private AuthProperties propertiesWithDomain(String accessDomain, String refreshDomain) {
        AuthProperties properties = new AuthProperties();
        properties.getJwt().setAccessTokenExpiration(900000L);
        properties.getJwt().setRefreshTokenExpiration(604800000L);

        properties.getCookies().getAccess().setDomain(accessDomain);
        properties.getCookies().getRefresh().setDomain(refreshDomain);

        return properties;
    }
}
