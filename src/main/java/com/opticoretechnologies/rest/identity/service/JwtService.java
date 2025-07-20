package com.opticoretechnologies.rest.identity.service;


import com.opticoretechnologies.rest.identity.jwk.JwkManager;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class JwtService {
    private final JwtEncoder jwtEncoder;
    private final JwkManager jwkManager;

    @Value("${app.jwt.access-token-expiration-sec}")
    private long accessTokenExpiration;


    public String generateToken(Authentication authentication) {

        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .subject(authentication.getName())
                .issuedAt(java.time.Instant.now())
                .expiresAt(java.time.Instant.now().plusSeconds(accessTokenExpiration))
                .claim("scope", scope)
                .id(java.util.UUID.randomUUID().toString())
                .build();

        JwtEncoderParameters encoderParameters = JwtEncoderParameters.from(claims);
        return this.jwtEncoder.encode(encoderParameters).getTokenValue();
    }

}
