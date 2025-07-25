package com.opticoretechnologies.rest.identity.service;


import com.opticoretechnologies.rest.identity.entity.RefreshToken;
import com.opticoretechnologies.rest.identity.entity.User;
import com.opticoretechnologies.rest.identity.repository.RefreshTokenRepository;
import com.opticoretechnologies.rest.identity.exception.RefreshTokenException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    @Value("${app.jwt.refresh-token-expiration-ms}")
    private Long refreshTokenDurationMs;
    private final TokenHashingService tokenHashingService;
    private final RefreshTokenRepository refreshTokenRepository;


    @Transactional
    public String createRefreshToken(User user, String deviceInfo) {
       String rawToken = generateRawToken();
       String hashedToken = tokenHashingService.hashToken(rawToken);

       RefreshToken refreshToken = RefreshToken.builder()
                .token(hashedToken)
                .user(user)
                .issuedAt(Instant.now())
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .revoked(false)
                .deviceInfo(deviceInfo)
                .build();
       refreshTokenRepository.save(refreshToken);
       return rawToken;
    }

    @Transactional(readOnly = true)
    public Optional<RefreshToken> validateRefreshToken(String rawToken) {
        String token = tokenHashingService.hashToken(rawToken);
        return refreshTokenRepository.findByToken(token)
                .filter(rt -> !rt.isRevoked())
                .filter(rt -> rt.getExpiryDate().isAfter(Instant.now()));
    }

    @Transactional
    public String rotateRefreshToken(String rawToken) {
        RefreshToken oldRefreshToken = validateRefreshToken(rawToken)
                .orElseThrow(() -> new RefreshTokenException("Invalid or expired refresh token"));

        oldRefreshToken.setRevoked(true);
        refreshTokenRepository.save(oldRefreshToken);
        return createRefreshToken(oldRefreshToken.getUser(), oldRefreshToken.getDeviceInfo());
    }

    @Transactional
    public void revokeRefreshToken(String rawToken) {

        validateRefreshToken(rawToken)
                .ifPresent(refreshToken -> {
                    refreshToken.setRevoked(true);
                    refreshTokenRepository.save(refreshToken);
                });
    }



    private String generateRawToken() {
        return UUID.randomUUID().toString()+"."+ Base64.getEncoder().encodeToString(UUID.randomUUID().toString().getBytes());
    }
}
