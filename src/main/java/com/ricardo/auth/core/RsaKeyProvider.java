package com.ricardo.auth.core;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Provides the RSA key pair used for JWT signing and verification.
 * <p>
 * Applications consuming this library can provide their own implementation
 * (e.g. loading keys from a secrets manager, keystore, or PEM files)
 * by declaring a bean of this type. If none is provided, a transient
 * in-memory key pair is generated on startup.
 */
public interface RsaKeyProvider {

    PrivateKey getPrivateKey();

    PublicKey getPublicKey();
}