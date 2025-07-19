package com.opticoretechnologies.rest.identity.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Represents a user in the system.
 * <p>
 * This entity is designed to be the aggregate root for user-related data and integrates
 * with Spring Security by implementing UserDetails.
 * <p>
 * We are intentionally avoiding Lombok's @Data, @ToString, and @EqualsAndHashCode
 * to prevent issues with lazy-loaded relationships, particularly potential
 * StackOverflowErrors in toString() or incorrect behavior in Sets.
 */
@Entity
@Table(name = "_users", indexes = {
        @Index(name = "idx_user_username_unq", columnList = "username", unique = true),
        @Index(name = "idx_user_email_unq", columnList = "email", unique = true)
})
@Getter
@Setter
@Builder
@AllArgsConstructor
@Slf4j
public class User implements UserDetails {

    // --- Constants ---
    private static final long serialVersionUID = 1L;

    // --- Primary Key ---
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(updatable = false)
    private UUID id;

    // --- Credentials & Personal Info ---
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

    // --- Account Status ---
    /**
     * If false, the user cannot log in. Can be used for manual admin locking.
     */
    @Builder.Default
    @Column(nullable = false)
    private boolean accountNonLocked = true;

    /**
     * If false, the user cannot log in. Typically used after an email verification process.
     */
    @Builder.Default
    @Column(nullable = false)
    private boolean enabled = false;

    // --- Relationships ---
    /**
     * The roles assigned to this user.
     * FetchType.EAGER is used here because authorities (derived from roles) are almost
     * always needed when a user is loaded for security checks.
     * CascadeType.PERSIST and MERGE ensure that if we save a user with a new, unsaved Role,
     * the Role will also be persisted.
     */
    @ManyToMany(fetch = FetchType.EAGER, cascade = {CascadeType.PERSIST, CascadeType.MERGE})
    @JoinTable(
            name = "_user_roles",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id")
    )
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    // --- Auditing ---
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    // --- Constructors ---
    public User() {
        this.roles = new HashSet<>();
        // Default status flags are set by @Builder.Default or direct initialization
    }

    // --- UserDetails Implementation ---

    /**
     * Derives authorities from the user's roles and their associated permissions.
     * This collects all unique permissions from all roles assigned to the user.
     *
     * @return A collection of GrantedAuthority representing the user's permissions.
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (roles == null || roles.isEmpty()) {
            log.warn("User ID {} has no roles assigned.", this.id);
            return Collections.emptySet();
        }
        return this.roles.stream()
                .flatMap(role -> role.getPermissions().stream()) // Stream all permissions from all roles
                .map(permission -> new SimpleGrantedAuthority(permission.getName()))
                .collect(Collectors.toSet()); // Use a Set to ensure no duplicate authorities
    }

    @Override
    public boolean isAccountNonExpired() {
        // We can add logic for this later if needed (e.g., based on a subscription date)
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // Can be used to force password resets periodically
        return true;
    }

    // --- Custom Logic Methods ---
    public void addRole(Role role) {
        this.roles.add(role);
        role.getUsers().add(this);
    }

    public void removeRole(Role role) {
        this.roles.remove(role);
        role.getUsers().remove(this);
    }

    // --- Object Identity Methods ---
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return Objects.equals(id, user.id) && Objects.equals(username, user.username);
    }

    @Override
    public int hashCode() {
        // Based on unique business key fields
        return Objects.hash(id, username);
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", enabled=" + enabled +
                ", accountNonLocked=" + accountNonLocked +
                ", roles=" + (roles != null ? roles.stream().map(Role::getName).collect(Collectors.joining(", ")) : "[]") +
                '}';
    }
}