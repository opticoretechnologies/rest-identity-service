package com.opticoretechnologies.rest.identity.service;


import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantReadWriteLock;

@Component
@EnableScheduling
@Slf4j

public class JwkService {
    private final List<RSAKey> keys = new ArrayList<>();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    private final boolean rotationEnabled;
    private final int keysToKeep;

    public JwkService(
            @Value("${app.security.jwk.rotation.enabled:true}") boolean rotationEnabled,
            @Value("${app.security.jwk.rotation.keys-to-keep:3}") int keysToKeep) {
        this.rotationEnabled = rotationEnabled;
        this.keysToKeep = keysToKeep;
        this.keys.add(generateRsaKey()); // Generate initial key on startup
        log.info("JwkService initialized. Rotation enabled: {}. Keys to keep: {}", rotationEnabled, keysToKeep);
    }

    /**
     * Returns the current key used for signing new JWTs.
     * This is always the most recently generated key.
     */
    public RSAKey getActiveSigningKey() {
        lock.readLock().lock();
        try {
            return keys.getFirst();
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Returns the JWK Set containing all PUBLIC keys.
     * This is for the /.well-known/jwks.json endpoint.
     */
    public JWKSet getJwkSet() {
        lock.readLock().lock();
        try {
            // The JWKSet constructor automatically creates a view with only public parameters.
            return new JWKSet((JWK) this.keys);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Finds the correct key by its ID and returns a verifier for it.
     * Used by JwtService to verify incoming tokens.
     */
    public Optional<JWSVerifier> findVerifierByKeyId(String keyId) {
        lock.readLock().lock();
        try {
            return keys.stream()
                    .filter(key -> key.getKeyID().equals(keyId))
                    .findFirst()
                    .map(key -> {
                        try {
                            return new RSASSAVerifier(key.toRSAPublicKey());
                        } catch (Exception e) {
                            log.error("Failed to create verifier for key ID: {}", keyId, e);
                            return null;
                        }
                    });
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Rotates the keys by generating a new key and removing old ones.
     * This method is called by a scheduled task.
     */
    public void rotateKeys() {
        if (!rotationEnabled) {
            return;
        }

        lock.writeLock().lock();
        try {
            log.info("Initiating JWK rotation...");
            this.keys.addFirst(generateRsaKey());
            while (this.keys.size() > keysToKeep) {
                RSAKey removedKey = keys.removeLast();
                log.info("Removed old JWK with key ID: {}", removedKey.getKeyID());
            }
            log.info("JWK rotation complete. Current number of keys: {}. Active key ID: {}", this.keys.size(), getActiveSigningKey().getKeyID());
        } finally {
            lock.writeLock().unlock();
        }
    }

    private RSAKey generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(UUID.randomUUID().toString())
                    .build();
        } catch (Exception e) {
            log.error("Failed to generate RSA key pair", e);
            throw new IllegalStateException("Failed to generate RSA key pair", e);
        }
    }
}