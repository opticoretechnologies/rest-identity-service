package com.opticoretechnologies.rest.identity.utils;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtils {

    @Value("${app.jwt.refresh-token-cookie-name}")
    private String refreshTokenCookieName;

    @Value("${app.jwt.refresh-token-expiration-ms}")
    private Long refreshTokenDurationMs;

    public void createRefreshTokenCookie(String rawToken, HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(refreshTokenCookieName, rawToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(refreshTokenDurationMs / 1000) // Convert milliseconds to seconds
                .sameSite("Strict") // Adjust as needed
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    public void clearRefreshTokenCookie(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(refreshTokenCookieName, "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(0) // Set max age to 0 to delete the cookie
                .sameSite("Strict") // Adjust as needed
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }
}