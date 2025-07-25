package com.opticoretechnologies.rest.identity.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Represents a user, serving as the security principal and aggregate root.
 *
 * --- Best Practices Implemented ---
 * 1.  @ToString(exclude = {"roles", "refreshTokens"}): Prevents recursion with both Role
 * and RefreshToken entities.
 * 2.  @EqualsAndHashCode(exclude = {"roles", "refreshTokens"}): Bases equality on user-specific
 * fields, not its collections, avoiding lazy loading and infinite loops.
 * 3.  FetchType.LAZY: Explicitly set on all collections to prevent the N+1 query problem.
 * Related data should be fetched on-demand with JOIN FETCH in the repository layer.
 * 4.  Cascade & Orphan Removal: The 'refreshTokens' relationship is configured to manage
 * the lifecycle of tokens automatically when a user is modified or deleted.
 */
@Entity
@Table(name = "_users", indexes = {
        @Index(name = "idx_user_username_unq", columnList = "username", unique = true),
        @Index(name = "idx_user_email_unq", columnList = "email", unique = true)
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(exclude = {"roles", "refreshTokens"})
@EqualsAndHashCode(exclude = {"roles", "refreshTokens"})
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(updatable = false)
    private UUID id;

    @NotEmpty(message = "Username cannot be empty.")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters.")
    @Column(nullable = false, unique = true, length = 50)
    private String username;

    @NotEmpty(message = "Password cannot be empty.")
    @Column(name = "password_hash", nullable = false)
    private String password;

    @Email(message = "Please provide a valid email address.")
    @NotEmpty(message = "Email cannot be empty.")
    @Column(nullable = false, unique = true, length = 100)
    private String email;

    @Builder.Default
    @Column(nullable = false)
    private boolean enabled = true;

    @Builder.Default
    @Column(nullable = false)
    private boolean accountNonLocked = true;

    // --- Relationships ---

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id")
    )
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    @OneToMany(
            mappedBy = "user",
            cascade = CascadeType.ALL,
            fetch = FetchType.LAZY,
            orphanRemoval = true
    )
    @Builder.Default
    private Set<RefreshToken> refreshTokens = new HashSet<>();

    // --- Auditing ---
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    // --- UserDetails Implementation ---

    /**
     * Derives authorities directly from the names of the roles assigned to the user.
     * Note: This requires the 'roles' collection to be initialized. If using lazy loading,
     * ensure roles are fetched before calling this method (e.g., via a JOIN FETCH query).
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (this.roles == null) {
            return Collections.emptySet();
        }
        return this.roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toSet());
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
}
