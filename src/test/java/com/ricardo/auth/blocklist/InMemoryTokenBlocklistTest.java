package com.ricardo.auth.blocklist;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The type In memory token blocklist test.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "ricardo.auth.blocklist.type=memory",
        "ricardo.auth.jwt.access-token-expiration=100",
        "ricardo.auth.jwt.secret=jrQBZmSULrzxVbDCxZk1BOqp3dOo95fp+ZA422w1GXs="
})
class InMemoryTokenBlocklistTest {
    @Autowired
    private InMemoryTokenBlocklist blocklist;


    @Test
    void testBlocklistInitialization() {
        assertNotNull(blocklist);
        assertInstanceOf(InMemoryTokenBlocklist.class, blocklist);
    }

    /**
     * Test revoke and is revoked.
     */
    @Test
    void testRevokeAndIsRevoked() {
        String token = "token123";
        assertFalse(blocklist.isRevoked(token));
        blocklist.revoke(token);
        assertTrue(blocklist.isRevoked(token));
    }

    /**
     * Test is revoked returns false for non revoked token.
     */
    @Test
    void testIsRevokedReturnsFalseForNonRevokedToken() {
        assertFalse(blocklist.isRevoked("notRevoked"));
    }

    /**
     * Test token expires.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    void testTokenExpires() throws InterruptedException {
        String token = "tokenExpire";
        blocklist.revoke(token);
        Thread.sleep(150); // Wait for token to expire
        assertFalse(blocklist.isRevoked(token));
    }

    /**
     * Test cleanup expired tokens removes expired.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    void testCleanupExpiredTokensRemovesExpired() throws InterruptedException {
        String token = "tokenCleanup";
        blocklist.revoke(token);
        Thread.sleep(150);
        blocklist.cleanupExpiredTokens();
        assertFalse(blocklist.isRevoked(token));
    }

    /**
     * Test null and empty token.
     */
    @Test
    void testNullAndEmptyToken() {
        assertThrows(IllegalArgumentException.class, () -> blocklist.revoke(null));
        assertThrows(IllegalArgumentException.class, () -> blocklist.revoke(""));
        assertThrows(IllegalArgumentException.class, () -> blocklist.isRevoked(null));
        assertThrows(IllegalArgumentException.class, () -> blocklist.isRevoked(""));
    }

    /**
     * Test revoke same token multiple times.
     */
    @Test
    void testRevokeSameTokenMultipleTimes() {
        String token = "dupToken";
        blocklist.revoke(token);
        blocklist.revoke(token);
        assertTrue(blocklist.isRevoked(token));
    }

    /**
     * Test is revoked with expired token.
     *
     * @throws InterruptedException the interrupted exception
     */
    @Test
    void testIsRevokedWithExpiredToken() throws InterruptedException {
        String token = "expiredToken";
        blocklist.revoke(token);
        Thread.sleep(150);
        assertFalse(blocklist.isRevoked(token));
        // Chamar novamente para garantir que não lança exceção
        assertFalse(blocklist.isRevoked(token));
    }

    /**
     * Test stress many tokens.
     */
    @Test
    void testStressManyTokens() {
        for (int i = 0; i < 1000; i++) {
            String token = "token" + i;
            blocklist.revoke(token);
            assertTrue(blocklist.isRevoked(token));
        }
    }
}
