package com.opticoretechnologies.rest.identity.repository;

import com.opticoretechnologies.rest.identity.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;


@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    // Custom query methods can be defined here if needed
    // For example:
    // Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);

    Optional<User> findByUsername(String username);

    String findPasswordHashByUsername(String username);

    boolean existsByEmail(String email);

    boolean existsByUsername(String username);
}