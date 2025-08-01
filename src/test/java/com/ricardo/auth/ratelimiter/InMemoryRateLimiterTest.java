package com.ricardo.auth.ratelimiter;

import com.ricardo.auth.autoconfig.AuthProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The type In memory rate limiter test.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "ricardo.auth.rate-limiter.type=memory",
        "ricardo.auth.rate-limiter.max-requests=2",
        "ricardo.auth.rate-limiter.time-window-ms=2000",
        "ricardo.auth.rate-limiter.enabled=true",
        "ricardo.auth.jwt.secret=jrQBZmSULrzxVbDCxZk1BOqp3dOo95fp+ZA422w1GXs="
})
class InMemoryRateLimiterTest {
    @Autowired
    private InMemoryRateLimiter rateLimiter;

    @Autowired
    private AuthProperties properties;


    /**
     * Test allow request within limit.
     */
    @Test
    void testAllowRequestWithinLimit() {
        String key = "user1";
        assertTrue(rateLimiter.allowRequest(key));
        assertTrue(rateLimiter.allowRequest(key));
        assertFalse(rateLimiter.allowRequest(key));
    }

    /**
     * Test allow request after window.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    void testAllowRequestAfterWindow() throws InterruptedException {
        String key = "user2";
        assertTrue(rateLimiter.allowRequest(key));
        assertTrue(rateLimiter.allowRequest(key));
        assertFalse(rateLimiter.allowRequest(key));
        Thread.sleep(2000);
        assertTrue(rateLimiter.allowRequest(key));
    }

    /**
     * Test is enabled.
     */
    @Test
    void testIsEnabled() {
        assertTrue(rateLimiter.isEnabled());
    }

    /**
     * Test cleanup old entries removes old.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    void testCleanupOldEntriesRemovesOld() throws InterruptedException {
        String key = "user3";
        rateLimiter.allowRequest(key);
        Thread.sleep(2100);
        rateLimiter.cleanupOldEntries();
        // After cleanup, should allow again
        assertTrue(rateLimiter.allowRequest(key));
    }

    /**
     * Test null and empty key.
     */
    @Test
    void testNullAndEmptyKey() {
        assertThrows(IllegalArgumentException.class, () -> rateLimiter.allowRequest(null));
        assertThrows(IllegalArgumentException.class, () -> rateLimiter.allowRequest(""));
    }

    /**
     * Test multiple keys independence.
     */
    @Test
    void testMultipleKeysIndependence() {
        String key1 = "userA";
        String key2 = "userB";
        assertTrue(rateLimiter.allowRequest(key1));
        assertTrue(rateLimiter.allowRequest(key2));
        assertTrue(rateLimiter.allowRequest(key1));
        assertTrue(rateLimiter.allowRequest(key2));
        assertFalse(rateLimiter.allowRequest(key1));
    }

    /**
     * Test max requests zero.
     */
    @Test
    void testMaxRequestsZero() {
        AuthProperties testProperties = new AuthProperties();
        testProperties.getRateLimiter().setMaxRequests(0);
        testProperties.getRateLimiter().setTimeWindowMs(2000L);
        testProperties.getRateLimiter().setEnabled(true);
    }

    /**
     * Test time window zero.
     */
    @Test
    void testTimeWindowZero() {
        AuthProperties testProperties = new AuthProperties();
        testProperties.getRateLimiter().setMaxRequests(2);
        testProperties.getRateLimiter().setTimeWindowMs(0L);
        testProperties.getRateLimiter().setEnabled(true);
        assertThrows(IllegalArgumentException.class, () -> new InMemoryRateLimiter(testProperties));
    }

    /**
     * Test negative max requests and window.
     */
    @Test
    void testNegativeMaxRequestsAndWindow() {
        AuthProperties testProperties = new AuthProperties();
        testProperties.getRateLimiter().setMaxRequests(-1);
        testProperties.getRateLimiter().setTimeWindowMs(-1L);
        testProperties.getRateLimiter().setEnabled(true);
        assertThrows(IllegalArgumentException.class, () -> new InMemoryRateLimiter(testProperties));
    }
}
