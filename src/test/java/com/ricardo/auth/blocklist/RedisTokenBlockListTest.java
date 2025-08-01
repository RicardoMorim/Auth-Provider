package com.ricardo.auth.blocklist;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.RedisSystemException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The type Redis token block list test.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "ricardo.auth.blocklist.type=redis",
        "ricardo.auth.jwt.access-token-expiration=1000",
        "ricardo.auth.jwt.secret=jrQBZmSULrzxVbDCxZk1BOqp3dOo95fp+ZA422w1GXs="
})
class RedisTokenBlockListTest {
    private final long ttlMillis = 1000L;
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    @Autowired
    private RedisTokenBlockList blockList;

    /**
     * Clean redis.
     */
    @BeforeEach
    void cleanRedis() {
        redisTemplate.getConnectionFactory().getConnection().flushDb();
    }

    @Test
    void testBlockListInitialization() {
        assertNotNull(blockList);
        assertInstanceOf(RedisTokenBlockList.class, blockList);
    }

    /**
     * Test revoke calls redis set.
     */
    @Test
    void testRevokeCallsRedisSet() {
        String token = "token1";
        blockList.revoke(token);
        String redisKey = "revoked:" + token;
        assertTrue(redisTemplate.hasKey(redisKey));
    }

    /**
     * Test is revoked returns true if key exists.
     */
    @Test
    void testIsRevokedReturnsTrueIfKeyExists() {
        String token = "token2";
        blockList.revoke(token);
        assertTrue(blockList.isRevoked(token));
    }

    /**
     * Test is revoked returns false if key not exists.
     */
    @Test
    void testIsRevokedReturnsFalseIfKeyNotExists() {
        assertFalse(blockList.isRevoked("token3"));
    }

    /**
     * Test null and empty token.
     */
    @Test
    void testNullAndEmptyToken() {
        assertThrows(IllegalArgumentException.class, () -> blockList.revoke(null));
        assertThrows(IllegalArgumentException.class, () -> blockList.revoke(""));
        assertThrows(IllegalArgumentException.class, () -> blockList.isRevoked(null));
        assertThrows(IllegalArgumentException.class, () -> blockList.isRevoked(""));
    }

    /**
     * Test revoke same token multiple times.
     */
    @Test
    void testRevokeSameTokenMultipleTimes() {
        String token = "dupToken";
        blockList.revoke(token);
        blockList.revoke(token);
        String redisKey = "revoked:" + token;
        assertTrue(redisTemplate.hasKey(redisKey));
    }

    /**
     * Test zero and negative ttl.
     */
    @Test
    void testZeroAndNegativeTTL() {
        RedisTokenBlockList zeroTtlBlockList = new RedisTokenBlockList(redisTemplate, 0L);
        RedisTokenBlockList negTtlBlockList = new RedisTokenBlockList(redisTemplate, -100L);
        assertThrows(RedisSystemException.class, () -> zeroTtlBlockList.revoke("tokenZero"));
        assertThrows(RedisSystemException.class, () -> negTtlBlockList.revoke("tokenNeg"));
    }

    /**
     * Test token expires after ttl.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    void testTokenExpiresAfterTTL() throws InterruptedException {
        String token = "expireToken";

        // First revoke the token (add it to the blocklist)
        blockList.revoke(token);

        // Verify it's revoked
        assertTrue(blockList.isRevoked(token));

        // Wait for expiration
        Thread.sleep(ttlMillis + 1000);

        // After TTL expires, the token should no longer be in the blocklist
        assertFalse(blockList.isRevoked(token));
    }

    /**
     * Test very long token.
     */
    @Test
    void testVeryLongToken() {
        String token = "t".repeat(200);
        blockList.revoke(token);
        String redisKey = "revoked:" + token;
        assertTrue(redisTemplate.hasKey(redisKey));
        assertTrue(blockList.isRevoked(token));
    }

    /**
     * Test special char token.
     */
    @Test
    void testSpecialCharToken() {
        String token = "tok:!@#$_-çãõ";
        blockList.revoke(token);
        String redisKey = "revoked:" + token;
        assertTrue(redisTemplate.hasKey(redisKey));
        assertTrue(blockList.isRevoked(token));
    }

    /**
     * Test concurrency.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    void testConcurrency() throws InterruptedException {
        String token = "concurrentToken";
        int threads = 10;
        boolean[] results = new boolean[threads];
        Thread[] arr = new Thread[threads];
        for (int i = 0; i < threads; i++) {
            int idx = i;
            arr[i] = new Thread(() -> {
                blockList.revoke(token + idx);
                results[idx] = blockList.isRevoked(token + idx);
            });
        }
        for (Thread t : arr) t.start();
        for (Thread t : arr) t.join();
        for (boolean b : results) assertTrue(b);
    }
}
