package com.ricardo.auth.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class InMemoryRsaKeyProviderTest {

    @Test
    void init_shouldGenerateKeyPair() {
        InMemoryRsaKeyProvider provider = new InMemoryRsaKeyProvider();

        provider.init();

        assertNotNull(provider.getPrivateKey());
        assertNotNull(provider.getPublicKey());
        assertEquals("RSA", provider.getPrivateKey().getAlgorithm());
        assertEquals("RSA", provider.getPublicKey().getAlgorithm());
    }
}
