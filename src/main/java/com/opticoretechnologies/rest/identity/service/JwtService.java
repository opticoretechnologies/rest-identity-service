package com.opticoretechnologies.rest.identity.service;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtService {
    private final JwkService jwkService;
    @Value("${app.jwt.access-token-expiration-sec}")
    private long accessTokenExpiration;

    public String extractUsername(String token) {
        return extractClaim(token, JWTClaimsSet::getSubject);
    }

    public <T> T extractClaim(String token, Function<JWTClaimsSet, T> claimsResolver) {
        final JWTClaimsSet claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        List<String> authorities = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(userDetails.getUsername())
                .issueTime(new Date(System.currentTimeMillis()))
                .expirationTime(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .claim("roles", authorities)
                .build();

        // Use the active signing key from JwkService
        var activeKey = jwkService.getActiveSigningKey();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(activeKey.getKeyID()) // Set the key ID in the header
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);

        try {
            signedJWT.sign(new RSASSASigner(activeKey));
            return signedJWT.serialize();
        } catch (Exception e) {
            log.error("Error signing JWT with key ID {}", activeKey.getKeyID(), e);
            throw new RuntimeException("Error signing JWT", e);
        }
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            return (username.equals(userDetails.getUsername())) && !isTokenExpired(token) && isSignatureValid(token);
        } catch (Exception e) {
            log.warn("JWT validation failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, claims -> claims.getExpirationTime());
    }

    private JWTClaimsSet extractAllClaims(String token) {
        try {
            return SignedJWT.parse(token).getJWTClaimsSet();
        } catch (ParseException e) {
            log.error("Could not parse JWT token", e);
            throw new RuntimeException("Invalid JWT token", e);
        }
    }

    private boolean isSignatureValid(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            String keyId = signedJWT.getHeader().getKeyID();

            if (keyId == null) {
                log.warn("JWT token does not contain key ID ('kid') in header.");
                return false;
            }

            // Find the correct verifier using the key ID from the token
            JWSVerifier verifier = jwkService.findVerifierByKeyId(keyId)
                    .orElseThrow(() -> new RuntimeException("No valid public key found for token key ID: " + keyId));

            return signedJWT.verify(verifier);
        } catch (Exception e) {
            log.warn("JWT signature verification failed", e);
            return false;
        }
    }
}
