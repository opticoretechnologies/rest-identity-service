package com.opticoretechnologies.rest.identity.controller;

import com.opticoretechnologies.rest.identity.dto.RegisterRequest;
import com.opticoretechnologies.rest.identity.entity.Role;
import com.opticoretechnologies.rest.identity.entity.User;
import com.opticoretechnologies.rest.identity.jwk.JwkManager;
import com.opticoretechnologies.rest.identity.repository.RoleRepository;
import com.opticoretechnologies.rest.identity.repository.UserRepository;
import com.opticoretechnologies.rest.identity.service.JwtService;
import com.opticoretechnologies.rest.identity.service.RefreshTokenService;
import com.opticoretechnologies.rest.identity.utils.CookieUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    @Autowired
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final JwkManager jwkManager;
    private final CookieUtils  cookieUtils;
    private final RoleRepository roleRepository;


    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest  registerRequest) {
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            return ResponseEntity.badRequest().body("Email is already in use");
        }

        if(userRepository.existsByUsername(registerRequest.getUsername())) {
            return ResponseEntity.badRequest().body("Username is already in use");
        }


        Role roleUser = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("ROLE_USER not found"));

        User user = User.builder()
                .username(registerRequest.getUsername())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .roles(Set.of(roleUser))
                .build();
        userRepository.save(user);

        return ResponseEntity.ok("User registered successfully");

    }

}
