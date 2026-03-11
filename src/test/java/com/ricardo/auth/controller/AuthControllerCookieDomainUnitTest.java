package com.ricardo.auth.controller;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.Publisher;
import com.ricardo.auth.core.RefreshTokenService;
import com.ricardo.auth.core.TokenBlocklist;
import com.ricardo.auth.core.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
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

    // --- Valid domain acceptance ---

    @ParameterizedTest
    @ValueSource(strings = {
        "example.com",
        ".example.com",
        "my-service.example.com",
        "auth2.example.com",
        "sub.auth.example.com",
        "0xdeadbeef.example.com"
    })
    void constructor_shouldAcceptValidDomain(String domain) {
        assertDoesNotThrow(() -> newController(propertiesWithDomain(domain, null)));
    }

    // --- isValidDomainStructure: invalid structure ---

    @Test
    void isValidDomainStructure_shouldRejectSingleLabel() {
        AuthController<?, ?, ?> controller = newController(propertiesWithDomain(null, null));
        Boolean result = ReflectionTestUtils.invokeMethod(controller, "isValidDomainStructure", "nodots");
        assertFalse(result);
    }

    @Test
    void isValidDomainStructure_shouldRejectLabelStartingWithHyphen() {
        AuthController<?, ?, ?> controller = newController(propertiesWithDomain(null, null));
        Boolean result = ReflectionTestUtils.invokeMethod(controller, "isValidDomainStructure", "-example.com");
        assertFalse(result);
    }

    @Test
    void isValidDomainStructure_shouldRejectLabelEndingWithHyphen() {
        AuthController<?, ?, ?> controller = newController(propertiesWithDomain(null, null));
        Boolean result = ReflectionTestUtils.invokeMethod(controller, "isValidDomainStructure", "example-.com");
        assertFalse(result);
    }

    @Test
    void isValidDomainStructure_shouldRejectEmptyLabel() {
        AuthController<?, ?, ?> controller = newController(propertiesWithDomain(null, null));
        Boolean result = ReflectionTestUtils.invokeMethod(controller, "isValidDomainStructure", "example..com");
        assertFalse(result);
    }

    @Test
    void isValidDomainStructure_shouldRejectLabelExceeding63Chars() {
        String longLabel = "a".repeat(64);
        AuthController<?, ?, ?> controller = newController(propertiesWithDomain(null, null));
        Boolean result = ReflectionTestUtils.invokeMethod(controller, "isValidDomainStructure", longLabel + ".com");
        assertFalse(result);
    }

    @Test
    void isValidDomainStructure_shouldRejectUnderscore() {
        AuthController<?, ?, ?> controller = newController(propertiesWithDomain(null, null));
        Boolean result = ReflectionTestUtils.invokeMethod(controller, "isValidDomainStructure", "my_service.example.com");
        assertFalse(result);
    }

    @Test
    void isValidDomainStructure_shouldRejectNonAsciiCharacters() {
        AuthController<?, ?, ?> controller = newController(propertiesWithDomain(null, null));
        Boolean result = ReflectionTestUtils.invokeMethod(controller, "isValidDomainStructure", "exämple.com");
        assertFalse(result);
    }

    // --- isValidDomainStructure: valid structure ---

    @Test
    void isValidDomainStructure_shouldAcceptValidTwoLevelDomain() {
        AuthController<?, ?, ?> controller = newController(propertiesWithDomain(null, null));
        Boolean result = ReflectionTestUtils.invokeMethod(controller, "isValidDomainStructure", "example.com");
        assertTrue(result);
    }

    @Test
    void isValidDomainStructure_shouldAcceptSubdomain() {
        AuthController<?, ?, ?> controller = newController(propertiesWithDomain(null, null));
        Boolean result = ReflectionTestUtils.invokeMethod(controller, "isValidDomainStructure", "auth.example.com");
        assertTrue(result);
    }

    @Test
    void isValidDomainStructure_shouldAcceptHyphenInMiddleOfLabel() {
        AuthController<?, ?, ?> controller = newController(propertiesWithDomain(null, null));
        Boolean result = ReflectionTestUtils.invokeMethod(controller, "isValidDomainStructure", "my-service.example.com");
        assertTrue(result);
    }

    @Test
    void isValidDomainStructure_shouldAcceptLabelOfExactly63Chars() {
        String maxLabel = "a".repeat(63);
        AuthController<?, ?, ?> controller = newController(propertiesWithDomain(null, null));
        Boolean result = ReflectionTestUtils.invokeMethod(controller, "isValidDomainStructure", maxLabel + ".com");
        assertTrue(result);
    }

    // --- constructor: domain length guard ---

    @Test
    void constructor_shouldRejectDomainExceeding253Chars() {
        // Build a domain with total length > 253 using valid-looking labels
        String label = "a".repeat(50);
        String longDomain = label + "." + label + "." + label + "." + label + "." + label + ".com";
        assertThrows(IllegalArgumentException.class, () ->
                newController(propertiesWithDomain(longDomain, null))
        );
    }

    // --- isDomainChar ---

    @Test
    void isDomainChar_shouldAcceptLowerCaseLetters() {
        AuthController<?, ?, ?> controller = newController(propertiesWithDomain(null, null));
        assertTrue((Boolean) ReflectionTestUtils.invokeMethod(controller, "isDomainChar", 'a'));
        assertTrue((Boolean) ReflectionTestUtils.invokeMethod(controller, "isDomainChar", 'z'));
    }

    @Test
    void isDomainChar_shouldAcceptDigits() {
        AuthController<?, ?, ?> controller = newController(propertiesWithDomain(null, null));
        assertTrue((Boolean) ReflectionTestUtils.invokeMethod(controller, "isDomainChar", '0'));
        assertTrue((Boolean) ReflectionTestUtils.invokeMethod(controller, "isDomainChar", '9'));
    }

    @Test
    void isDomainChar_shouldRejectHyphen() {
        AuthController<?, ?, ?> controller = newController(propertiesWithDomain(null, null));
        assertFalse((Boolean) ReflectionTestUtils.invokeMethod(controller, "isDomainChar", '-'));
    }

    @Test
    void isDomainChar_shouldRejectUpperCaseLetters() {
        AuthController<?, ?, ?> controller = newController(propertiesWithDomain(null, null));
        assertFalse((Boolean) ReflectionTestUtils.invokeMethod(controller, "isDomainChar", 'A'));
        assertFalse((Boolean) ReflectionTestUtils.invokeMethod(controller, "isDomainChar", 'Z'));
    }

    @Test
    void isDomainChar_shouldRejectSpecialCharacters() {
        AuthController<?, ?, ?> controller = newController(propertiesWithDomain(null, null));
        assertFalse((Boolean) ReflectionTestUtils.invokeMethod(controller, "isDomainChar", '_'));
        assertFalse((Boolean) ReflectionTestUtils.invokeMethod(controller, "isDomainChar", '.'));
        assertFalse((Boolean) ReflectionTestUtils.invokeMethod(controller, "isDomainChar", '@'));
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
