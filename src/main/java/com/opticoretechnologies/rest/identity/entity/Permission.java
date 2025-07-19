package com.opticoretechnologies.rest.identity.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotEmpty;
import lombok.*;

import java.util.Objects;
import java.util.UUID;

/**
 * Represents a single, granular permission in the system (e.g., 'user:read', 'product:create').
 * These are the building blocks for roles. This entity is designed to be a simple lookup table.
 */
@Entity
@Table(name = "_permissions", indexes = {
        @Index(name = "idx_permission_name_unq", columnList = "name", unique = true)
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Permission {

    // --- Primary Key ---
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(updatable = false)
    private UUID id;

    // --- Core Fields ---
    @NotEmpty(message = "Permission name cannot be empty.")
    @Column(nullable = false, unique = true, length = 100)
    private String name;

    @Column(length = 255)
    private String description;

    // --- Object Identity Methods ---
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Permission that = (Permission) o;
        return Objects.equals(name, that.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name);
    }

    @Override
    public String toString() {
        return "Permission{" +
                "id=" + id +
                ", name='" + name + '\'' +
                '}';
    }
}
