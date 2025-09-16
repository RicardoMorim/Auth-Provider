package com.ricardo.auth.ratelimiter;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The type Redis rate limiter test.
 */
@Slf4j
@SpringBootTest
@TestPropertySource(properties = {
        "ricardo.auth.rate-limiter.type=redis",
        "ricardo.auth.rate-limiter.max-requests=2",
        "ricardo.auth.rate-limiter.time-window-ms=2000",
        "ricardo.auth.rate-limiter.enabled=true",
        "ricardo.auth.jwt.secret=jrQBZmSULrzxVbDCxZk1BOqp3dOo95fp+ZA422w1GXs="
})
class RedisRateLimiterTest {
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    @Autowired
    private RedisRateLimiter rateLimiter;

    /**
     * Clean redis.
     */
    @BeforeEach
    void cleanRedis() {
        // Make sure each test gets clean Redis state
        redisTemplate.getConnectionFactory().getConnection().flushDb();
    }

    /**
     * Context loads.
     */
    @Test
    void contextLoads() {
        // Context loads test
        assertNotNull(redisTemplate);
        log.info("Max Requests: {}, Time Window (ms): {}, ", rateLimiter.getMaxRequests(), rateLimiter.getWindowMillis());
    }

    /**
     * Test rate limiter initialization.
     */
    @Test
    void testRateLimiterInitialization() {
        assertNotNull(rateLimiter);
        assertInstanceOf(RedisRateLimiter.class, rateLimiter);
    }

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
     * Test allow request exceeds limit.
     */
    @Test
    void testAllowRequestExceedsLimit() {
        String key = "user2";
        assertTrue(rateLimiter.allowRequest(key));
        assertTrue(rateLimiter.allowRequest(key));
        assertFalse(rateLimiter.allowRequest(key));
    }

    /**
     * Test is enabled.
     */
    @Test
    void testIsEnabled() {
        assertTrue(rateLimiter.isEnabled());
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
        assertFalse(rateLimiter.allowRequest(key2));
    }

    /**
     * Test allow request after window.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    void testAllowRequestAfterWindow() throws InterruptedException {
        String key = "userExpire";
        assertTrue(rateLimiter.allowRequest(key));
        assertTrue(rateLimiter.allowRequest(key));
        assertFalse(rateLimiter.allowRequest(key));
        Thread.sleep(3000); // Espera passar a janela
        assertTrue(rateLimiter.allowRequest(key));
    }

    /**
     * Test very long key.
     */
    @Test
    void testVeryLongKey() {
        String key = "k".repeat(200);
        assertTrue(rateLimiter.allowRequest(key));
        assertTrue(rateLimiter.allowRequest(key));
        assertFalse(rateLimiter.allowRequest(key));
    }

    /**
     * Test special char key.
     */
    @Test
    void testSpecialCharKey() {
        String key = "user:!@#$_-çãõ";
        assertTrue(rateLimiter.allowRequest(key));
        assertTrue(rateLimiter.allowRequest(key));
        assertFalse(rateLimiter.allowRequest(key));
    }

    /**
     * Test concurrency same key.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    void testConcurrencySameKey() throws InterruptedException {
        String key = "concurrentUser";
        int threads = 10;
        int[] allowed = {0};
        Thread[] arr = new Thread[threads];
        for (int i = 0; i < threads; i++) {
            arr[i] = new Thread(() -> {
                if (rateLimiter.allowRequest(key)) {
                    synchronized (allowed) {
                        allowed[0]++;
                    }
                }
            });
        }
        for (Thread t : arr) t.start();
        for (Thread t : arr) t.join();
        assertEquals(2, allowed[0]);
    }

    /**
     * Test concurrency multiple keys.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    void testConcurrencyMultipleKeys() throws InterruptedException {
        int threads = 10;
        int[] allowed = {0};
        Thread[] arr = new Thread[threads];
        for (int i = 0; i < threads; i++) {
            String key = "user" + i;
            arr[i] = new Thread(() -> {
                if (rateLimiter.allowRequest(key)) {
                    synchronized (allowed) {
                        allowed[0]++;
                    }
                }
            });
        }
        for (Thread t : arr) t.start();
        for (Thread t : arr) t.join();
        assertEquals(10, allowed[0]); // Cada chave é independente
    }
}
