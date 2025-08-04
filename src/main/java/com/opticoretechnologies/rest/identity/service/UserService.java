package com.opticoretechnologies.rest.identity.service;

import com.opticoretechnologies.rest.identity.dto.AuthResponse;
import com.opticoretechnologies.rest.identity.dto.UpdatePasswordRequest;
import com.opticoretechnologies.rest.identity.dto.UpdateUsernameRequest;
import com.opticoretechnologies.rest.identity.dto.UserInfo;
import com.opticoretechnologies.rest.identity.entity.User;
import com.opticoretechnologies.rest.identity.exception.BadRequestException;
import com.opticoretechnologies.rest.identity.exception.DuplicateResourceException;
import com.opticoretechnologies.rest.identity.exception.ResourceNotFoundException;
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
    private final RefreshTokenService refreshTokenService;


    @Transactional
    public AuthResponse updateUsername(String currentUsername, UpdateUsernameRequest request) throws DuplicateResourceException, UsernameNotFoundException {
        if (userRepository.existsByUsername(request.getNewUsername())) {
            throw new ResourceNotFoundException("USER_NAME" , request.getNewUsername() ,"is already taken");
        }
        User user = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new ResourceNotFoundException("USER_NAME", request.getNewUsername(),"is already taken"));
        user.setUsername(request.getNewUsername());
        User updatedUser = userRepository.save(user);
        String newAccessToken = jwtService.generateToken(updatedUser);
        return AuthResponse.builder().accessToken(newAccessToken).tokenType("Bearer").userInfo(UserInfo.builder().username(updatedUser.getUsername()).email(updatedUser.getEmail()).build()).build();
    }

    @Transactional
    public String updatePassword(String username, UpdatePasswordRequest request, String deviceInfo) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User", "username", username));
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new BadRequestException("Incorrect current password.");
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
