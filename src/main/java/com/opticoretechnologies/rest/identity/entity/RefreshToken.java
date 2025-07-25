package com.opticoretechnologies.rest.identity.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotEmpty;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Represents a refresh token for a user, allowing for extended sessions.
 *
 * --- Best Practices Implemented ---
 * 1.  @ToString(exclude = "user"): Prevents a StackOverflowError by breaking the chain:
 * RefreshToken.toString() -> User.toString() -> RefreshToken.toString().
 * 2.  @EqualsAndHashCode(exclude = "user"): Bases equality on the token's own data, not the
 * user it belongs to, avoiding recursion and lazy-loading issues.
 * 3.  FetchType.LAZY: The relationship to the User is lazy, as you often only need to
 * validate the token itself without loading the full user object.
 * 4.  @GeneratedValue on ID: Removes the need for @NotEmpty validation, as the persistence
 * provider guarantees the ID's existence.
 */
@Entity
@Table(name = "_refresh_tokens", indexes = {
        @Index(name = "idx_refresh_token_value_unq", columnList = "token", unique = true)
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(exclude = "user")
@EqualsAndHashCode(exclude = "user")
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    @NotEmpty(message = "Refresh token value cannot be empty.")
    private String token;

    /**
     * The user this token belongs to.
     * `optional = false` makes this a required relationship at the database level.
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private Instant issuedAt;

    @Column(nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    private boolean revoked;

    private String deviceInfo;
}
