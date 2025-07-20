package com.opticoretechnologies.rest.identity.jwk;


import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;

@Component
@EnableScheduling
@Slf4j

public class JwkManager {
    @Getter
    private final List<RSAKey> keys = new LinkedList<>();
    private final boolean rotationEnabled;
    private final int keysToKeep;

    public JwkManager(@Value("${app.security.jwk.rotation.enabled}") boolean rotationEnabled,
                      @Value("${app.security.jwk.rotation.keys-to-keep}") int keysToKeep) {
        this.rotationEnabled = rotationEnabled;
        this.keysToKeep = keysToKeep;
        this.keys.add(generateRsaKey());
    }


    public RSAKey getLatestKey(){
        if (keys.isEmpty()) {
            log.warn("No RSA keys available in JwkManager.");
            return null;
        }
        return keys.getFirst();
    }
    public JWKSet getJwkSet() {
        return new JWKSet((JWK) this.keys);
    }

    public void rotateKeys(){
        if (!rotationEnabled) {
            log.info("JWK rotation is disabled. Skipping key rotation.");
            return;
        }

        this.keys.addFirst(generateRsaKey());
        while (this.keys.size() > keysToKeep) {
            keys.removeLast();
        }

        log.info("JWK rotation complete. Current number of keys: {}", this.keys.size());

    }

    private RSAKey generateRsaKey() {

        try{
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // Use 2048 bits for RSA key size
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(java.util.UUID.randomUUID().toString()) // Generate a unique key ID
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
