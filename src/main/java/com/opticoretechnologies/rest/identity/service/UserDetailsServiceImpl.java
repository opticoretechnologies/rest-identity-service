package com.opticoretechnologies.rest.identity.service;

import com.opticoretechnologies.rest.identity.entity.User;
import com.opticoretechnologies.rest.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

    @Service
    @RequiredArgsConstructor
    @Slf4j
    public class UserDetailsServiceImpl implements UserDetailsService {
        private final UserRepository userRepository;
        @Override @Transactional(readOnly = true)
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            return userRepository.findByUsernameWithRoles(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));
        }
    }
