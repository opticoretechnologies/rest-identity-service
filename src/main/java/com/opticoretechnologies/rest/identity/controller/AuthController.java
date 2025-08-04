package com.opticoretechnologies.rest.identity.controller;

import com.opticoretechnologies.rest.identity.dto.AuthResponse;
import com.opticoretechnologies.rest.identity.dto.LoginRequest;
import com.opticoretechnologies.rest.identity.dto.RegisterRequest;
import com.opticoretechnologies.rest.identity.exception.DuplicateResourceException;
import com.opticoretechnologies.rest.identity.exception.TokenException;
import com.opticoretechnologies.rest.identity.service.AuthService;
import com.opticoretechnologies.rest.identity.service.JwkService;
import com.opticoretechnologies.rest.identity.service.JwtService;
import com.opticoretechnologies.rest.identity.service.RefreshTokenService;
import com.opticoretechnologies.rest.identity.utils.CookieUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final JwkService jwkService;
    private final CookieUtils cookieUtils;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) throws DuplicateResourceException {
        log.info("Registering user with username: {}", registerRequest.getUsername());
        authService.register(registerRequest);
        return ResponseEntity.ok(Map.of("message", "User registered successfully!"));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@CookieValue(name = "${app.jwt.refresh-token-cookie-name}", required = false) String rawRefreshToken, HttpServletResponse response)  {
        if (rawRefreshToken == null) {
            throw new TokenException("Refresh token is missing.");
        }
        return refreshTokenService.validateRefreshToken(rawRefreshToken)
                .map(refreshTokenEntity -> {
                    UserDetails userDetails = refreshTokenEntity.getUser();
                    String newAccessToken = jwtService.generateToken(userDetails);
                    String newRawRefreshToken = refreshTokenService.rotateRefreshToken(rawRefreshToken);
                    cookieUtils.createRefreshTokenCookie(newRawRefreshToken, response); // <-- Use CookieUtils
                    return ResponseEntity.ok(AuthResponse.builder().accessToken(newAccessToken).tokenType("Bearer").build());
                })
                .orElseThrow(() -> new TokenException("Refresh token is invalid or expired!"));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(@CookieValue(name = "${app.jwt.refresh-token-cookie-name}", required = false) String rawRefreshToken, HttpServletResponse response) {
        if (rawRefreshToken != null) {
            refreshTokenService.revokeRefreshToken(rawRefreshToken);
        }
        cookieUtils.clearRefreshTokenCookie(response); // <-- Use CookieUtils
        return ResponseEntity.ok(Map.of("message", "You've been signed out successfully."));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest, HttpServletRequest request, HttpServletResponse response) {
        String device = request.getHeader(HttpHeaders.USER_AGENT);
        String ipAddress = request.getRemoteAddr();
        String deviceInfo = String.format("User-Agent: %s, IP Address: %s", device, ipAddress);
        AuthResponse authResponse = authService.login(loginRequest, deviceInfo, request);
//        log.info("Auth response: {}", authResponse.toString());

        String rawRefreshToken = authResponse.getTokenType();
        cookieUtils.createRefreshTokenCookie(rawRefreshToken, response);

        authResponse.setTokenType("Bearer");
        return ResponseEntity.ok(authResponse);
    }

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> getJwkSet() {
        return ResponseEntity.ok(jwkService.getJwkSet().toJSONObject());
    }
}
