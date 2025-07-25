package com.opticoretechnologies.rest.identity.controller;

import com.opticoretechnologies.rest.identity.dto.AuthResponse;
import com.opticoretechnologies.rest.identity.dto.LoginRequest;
import com.opticoretechnologies.rest.identity.dto.RegisterRequest;
import com.opticoretechnologies.rest.identity.exception.TokenRefreshException;
import com.opticoretechnologies.rest.identity.exception.UserAlreadyExistsException;
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

import javax.management.relation.RoleNotFoundException;
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
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) throws RoleNotFoundException, UserAlreadyExistsException {
        authService.register(registerRequest);
        return ResponseEntity.ok(Map.of("message", "User registered successfully!"));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@CookieValue(name = "${app.jwt.refresh-token-cookie-name}", required = false) String rawRefreshToken, HttpServletResponse response) throws TokenRefreshException {
        if (rawRefreshToken == null) {
            throw new TokenRefreshException("Refresh token is missing.");
        }
        return refreshTokenService.validateRefreshToken(rawRefreshToken)
                .map(refreshTokenEntity -> {
                    UserDetails userDetails = refreshTokenEntity.getUser();
                    String newAccessToken = jwtService.generateToken(userDetails);
                    String newRawRefreshToken = refreshTokenService.rotateRefreshToken(rawRefreshToken);
                    cookieUtils.createRefreshTokenCookie(newRawRefreshToken, response); // <-- Use CookieUtils
                    return ResponseEntity.ok(AuthResponse.builder().accessToken(newAccessToken).tokenType("Bearer").build());
                })
                .orElseThrow(() -> new TokenRefreshException("Refresh token is invalid or expired!"));
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
        String deviceInfo = request.getHeader(HttpHeaders.USER_AGENT);
        AuthResponse authResponse = authService.login(loginRequest, deviceInfo);
        // The raw refresh token is temporarily stored in the tokenType field
        String rawRefreshToken = authResponse.getTokenType();
        cookieUtils.createRefreshTokenCookie(rawRefreshToken, response);
        // Set the tokenType to the standard "Bearer" before sending to the client
        authResponse.setTokenType("Bearer");
        return ResponseEntity.ok(authResponse);
    }

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> getJwkSet() {
        return ResponseEntity.ok(jwkService.getJwkSet().toJSONObject());
    }
}
