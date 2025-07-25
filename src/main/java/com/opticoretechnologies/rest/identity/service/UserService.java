package com.opticoretechnologies.rest.identity.service;

import com.opticoretechnologies.rest.identity.dto.AuthResponse;
import com.opticoretechnologies.rest.identity.dto.UpdatePasswordRequest;
import com.opticoretechnologies.rest.identity.dto.UpdateUsernameRequest;
import com.opticoretechnologies.rest.identity.dto.UserInfo;
import com.opticoretechnologies.rest.identity.entity.User;
import com.opticoretechnologies.rest.identity.exception.UserAlreadyExistsException;
import com.opticoretechnologies.rest.identity.repository.RefreshTokenRepository;
import com.opticoretechnologies.rest.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Setter
@RequiredArgsConstructor
@Slf4j
@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenService refreshTokenService; // <-- Injected RefreshTokenService

    @Transactional
    public AuthResponse updateUsername(String currentUsername, UpdateUsernameRequest request) throws UserAlreadyExistsException {
        // ... same as before
        if (userRepository.existsByUsername(request.getNewUsername())) {
            throw new UserAlreadyExistsException("Username '" + request.getNewUsername() + "' is already taken.");
        }
        User user = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        user.setUsername(request.getNewUsername());
        User updatedUser = userRepository.save(user);
        String newAccessToken = jwtService.generateToken(updatedUser);
        return AuthResponse.builder().accessToken(newAccessToken).tokenType("Bearer").userInfo(UserInfo.builder().username(updatedUser.getUsername()).email(updatedUser.getEmail()).build()).build();
    }

    @Transactional
    public String updatePassword(String username, UpdatePasswordRequest request, String deviceInfo) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Incorrect current password.");
        }
        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
        // Revoke all old sessions
        refreshTokenRepository.deleteByUser(user);
        // Create a new refresh token for the current session to keep it active
        return refreshTokenService.createRefreshToken(user, deviceInfo);
    }
}
