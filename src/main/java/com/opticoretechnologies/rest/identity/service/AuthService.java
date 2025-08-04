package com.opticoretechnologies.rest.identity.service;

import com.opticoretechnologies.rest.identity.dto.AuthResponse;
import com.opticoretechnologies.rest.identity.dto.LoginRequest;
import com.opticoretechnologies.rest.identity.dto.RegisterRequest;
import com.opticoretechnologies.rest.identity.dto.UserInfo;
import com.opticoretechnologies.rest.identity.entity.Role;
import com.opticoretechnologies.rest.identity.entity.User;
import com.opticoretechnologies.rest.identity.exception.DuplicateResourceException;
import com.opticoretechnologies.rest.identity.repository.RoleRepository;
import com.opticoretechnologies.rest.identity.repository.UserRepository;
import com.opticoretechnologies.rest.identity.utils.CookieUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.management.relation.RoleNotFoundException;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final CookieUtils cookieUtils;

    @Transactional
    public void register(RegisterRequest request) throws DuplicateResourceException {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new DuplicateResourceException("Username is already taken!");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateResourceException("Email is already in use!");
        }
        Role userRole = null;
        try {
            userRole = roleRepository.findByName("ROLE_USER").orElseThrow(() -> new RoleNotFoundException("Role USER not found. Please initialize roles."));
        } catch (RoleNotFoundException e) {
            userRole = roleRepository.save(Role.builder().name("ROLE_USER").description("Default user role").build());
        }
        User user = User.builder().username(request.getUsername()).email(request.getEmail()).password(passwordEncoder.encode(request.getPassword())).roles(Set.of(userRole)).enabled(true).accountNonLocked(true).build();
        userRepository.save(user);
    }


    public AuthResponse login(LoginRequest request, String deviceInfo, HttpServletRequest httpServletRequest) {

        if (request == null || request.getUsername() == null || request.getPassword() == null) {
            throw new IllegalArgumentException("Username and password must be provided.");
        }

        // Check for existing refresh token in cookies
        String existingRefreshToken = cookieUtils.getRefreshTokenFromCookie(httpServletRequest);
        if (existingRefreshToken != null) {
            // Validate the existing refresh token
            var refreshToken = refreshTokenService.validateRefreshToken(existingRefreshToken);
            if (refreshToken.isPresent()) {
                log.info("Duplicate refresh token found for user: {}", refreshToken.get().getUser().getUsername());
                String newRefreshToken = refreshTokenService.rotateRefreshToken(existingRefreshToken);
                String accessToken = jwtService.generateToken(refreshToken.get().getUser());
                return AuthResponse.builder()
                        .accessToken(accessToken)
                        .userInfo(UserInfo.builder()
                                .username(refreshToken.get().getUser().getUsername())
                                .email(refreshToken.get().getUser().getEmail())
                                .build())
                        .tokenType(newRefreshToken)
                        .build();
            }
        }

        // Normal login process when no valid refresh token exists
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
        } catch (Exception ex) {
            throw new SecurityException("Invalid username or password.", ex);
        }

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new SecurityException("Authentication failed.");
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        Object principal = authentication.getPrincipal();
        if (!(principal instanceof User userDetails)) {
            throw new IllegalStateException("Authenticated principal is not of type User.");
        }

        if (!userDetails.isEnabled()) {
            throw new SecurityException("User account is disabled.");
        }
        if (!userDetails.isAccountNonLocked()) {
            throw new SecurityException("User account is locked.");
        }

        String accessToken;
        try {
            accessToken = jwtService.generateToken(userDetails);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate access token.", ex);
        }

        String rawRefreshToken;
        try {
            rawRefreshToken = refreshTokenService.createRefreshToken(userDetails, deviceInfo);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to create refresh token.", ex);
        }

        return AuthResponse.builder()
                .accessToken(accessToken)
                .userInfo(UserInfo.builder()
                        .username(userDetails.getUsername())
                        .email(userDetails.getEmail())
                        .build())
                .tokenType(rawRefreshToken)
                .build();
    }



}

