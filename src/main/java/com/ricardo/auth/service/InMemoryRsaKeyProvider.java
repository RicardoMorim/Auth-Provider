package com.ricardo.auth.service;

import com.ricardo.auth.core.RsaKeyProvider;
import jakarta.annotation.PostConstruct;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Default RSA key provider that generates a transient key pair on startup.
 * Tokens will NOT survive application restarts.
 * <p>
 * Replace this bean with your own {@link RsaKeyProvider} to use
 * persistent keys (e.g. from a secrets manager or keystore).
 */
public class InMemoryRsaKeyProvider implements RsaKeyProvider {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    @PostConstruct
    public void init() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);

            KeyPair pair = generator.generateKeyPair();
            this.privateKey = pair.getPrivate();
            this.publicKey = pair.getPublic();

        } catch (Exception e) {
            throw new IllegalStateException("Failed generating RSA key pair", e);
        }
    }

    @Override
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }
}