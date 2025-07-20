package com.opticoretechnologies.rest.identity.controller;

import com.opticoretechnologies.rest.identity.jwk.JwkManager;
import com.opticoretechnologies.rest.identity.repository.UserRepository;
import com.opticoretechnologies.rest.identity.service.JwtService;
import com.opticoretechnologies.rest.identity.service.RefreshTokenService;
import com.opticoretechnologies.rest.identity.service.TokenBlacklistService;
import com.opticoretechnologies.rest.identity.utils.CookieUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final JwkManager jwkManager;
    private final TokenBlacklistService tokenBlacklistService;
    private final CookieUtils  cookieUtils;



}
