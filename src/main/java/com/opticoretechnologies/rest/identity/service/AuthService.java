package com.opticoretechnologies.rest.identity.service;

import com.opticoretechnologies.rest.identity.dto.AuthResponse;
import com.opticoretechnologies.rest.identity.dto.LoginRequest;
import com.opticoretechnologies.rest.identity.dto.RegisterRequest;
import com.opticoretechnologies.rest.identity.dto.UserInfo;
import com.opticoretechnologies.rest.identity.entity.Role;
import com.opticoretechnologies.rest.identity.entity.User;
import com.opticoretechnologies.rest.identity.exception.UserAlreadyExistsException;
import com.opticoretechnologies.rest.identity.repository.RoleRepository;
import com.opticoretechnologies.rest.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
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
public class AuthService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    @Transactional
    public void register(RegisterRequest request) throws  UserAlreadyExistsException {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UserAlreadyExistsException("Username is already taken!");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("Email is already in use!");
        }
        Role userRole = null;
        try {
            userRole = roleRepository.findByName("ROLE_USER").orElseThrow(() -> new RoleNotFoundException("Role USER not found. Please initialize roles."));
        } catch (RoleNotFoundException e) {
           userRole = roleRepository.save( Role.builder().name("ROLE_USER").description("Default user role").build());
        }
        User user = User.builder().username(request.getUsername()).email(request.getEmail()).password(passwordEncoder.encode(request.getPassword())).roles(Set.of(userRole)).enabled(true).accountNonLocked(true).build();
        userRepository.save(user);
    }
    public AuthResponse login(LoginRequest request, String deviceInfo) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        User userDetails = (User) authentication.getPrincipal();
        String accessToken = jwtService.generateToken(userDetails);
        String rawRefreshToken = refreshTokenService.createRefreshToken(userDetails, deviceInfo);
        return AuthResponse.builder().accessToken(accessToken).userInfo(UserInfo.builder().username(userDetails.getUsername()).email(userDetails.getEmail()).build()).tokenType(rawRefreshToken).build();
    }
}

