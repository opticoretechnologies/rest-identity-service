package com.opticoretechnologies.rest.identity.repository;

import com.opticoretechnologies.rest.identity.entity.RefreshToken;
import com.opticoretechnologies.rest.identity.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    /**
     * Finds a RefreshToken by its token string.
     *
     * @param token the token string to search for
     * @return an Optional containing the RefreshToken if found, or empty if not found
     */
    Optional<RefreshToken> findByToken(String token);

    /**
     * Deletes a RefreshToken by its token string.
     *
     * @param token the token string to delete
     */
    void deleteByToken(String token);

    void deleteRevokedTokensByUserId(UUID userId);
    void deleteExpiredTokensByUserId(UUID userId);
    void deleteAllByUserId(UUID userId);

    void deleteByUser(User user);
}
