package com.opticoretechnologies.rest.identity.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotEmpty;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Represents a role within the system (e.g., ROLE_ADMIN, ROLE_USER).
 * In this model, the role's name is directly used as the authority granted to a user.
 *
 * --- Best Practices Implemented ---
 * 1.  @ToString(exclude = "users"): Prevents a StackOverflowError by stopping the chain:
 * Role.toString() -> User.toString() -> Role.toString().
 * 2.  @EqualsAndHashCode(exclude = "users"): Ensures that equality checks don't trigger
 * lazy loading of the entire users collection and avoids recursive loops.
 * Equality is based on the role's own fields (id, name), not the users who have it.
 * 3.  The 'users' collection is LAZY fetched by default on @ManyToMany.
 */
@Entity
@Table(name = "_roles", indexes = {
        @Index(name = "idx_role_name_unq", columnList = "name", unique = true)
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(exclude = "users")
@EqualsAndHashCode(exclude = "users")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(updatable = false)
    private UUID id;

    @NotEmpty(message = "Role name cannot be empty.")
    @Column(nullable = false, unique = true, length = 50)
    private String name;

    @Column(length = 255)
    private String description;

    /**
     * The users who have this role. This is the "inverse" side of the relationship.
     * It is mapped by the 'roles' field in the User entity.
     * Fetching is LAZY by default, which is critical for performance.
     */
    @ManyToMany(mappedBy = "roles", fetch = FetchType.LAZY)
    @Builder.Default
    private Set<User> users = new HashSet<>();

    // --- Auditing ---
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
