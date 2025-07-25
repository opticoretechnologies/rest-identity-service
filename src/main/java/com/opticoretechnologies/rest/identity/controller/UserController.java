package com.opticoretechnologies.rest.identity.controller;


import com.opticoretechnologies.rest.identity.dto.AuthResponse;
import com.opticoretechnologies.rest.identity.dto.UpdatePasswordRequest;
import com.opticoretechnologies.rest.identity.dto.UpdateUsernameRequest;
import com.opticoretechnologies.rest.identity.exception.UserAlreadyExistsException;
import com.opticoretechnologies.rest.identity.service.JwtService;
import com.opticoretechnologies.rest.identity.service.UserService;
import com.opticoretechnologies.rest.identity.utils.CookieUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final JwtService jwtService;
    private final CookieUtils cookieUtils;

    @PatchMapping("/update/password")
    public ResponseEntity<AuthResponse> updatePassword(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody UpdatePasswordRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        String deviceInfo = httpRequest.getHeader(HttpHeaders.USER_AGENT);
        // This method now returns the new raw refresh token
        String newRawRefreshToken = userService.updatePassword(userDetails.getUsername(), request, deviceInfo);

        // Issue a new access token
        String newAccessToken = jwtService.generateToken(userDetails);

        // Set the new refresh token in the cookie
        cookieUtils.createRefreshTokenCookie(newRawRefreshToken, httpResponse);

        // Return the new access token to the client
        return ResponseEntity.ok(AuthResponse.builder().accessToken(newAccessToken).tokenType("Bearer").build());
    }

    @GetMapping("/me")
    public ResponseEntity<UserDetails> getCurrentUser(@AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(userDetails);
    }

    @PatchMapping("/update/username")
    public ResponseEntity<AuthResponse> updateUsername(@AuthenticationPrincipal UserDetails userDetails, @Valid @RequestBody UpdateUsernameRequest request) throws UserAlreadyExistsException {
        AuthResponse authResponse = userService.updateUsername(userDetails.getUsername(), request);
        return ResponseEntity.ok(authResponse);
    }
}
