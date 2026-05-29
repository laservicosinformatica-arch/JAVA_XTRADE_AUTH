package com.xtrade.auth.xtrade_auth_server.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@Table(name = "app_roles")
public class AppRole {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * No Spring Security vamos transformar em ROLE_ADMIN, ROLE_USER etc.
     */
    @Column(nullable = false, unique = true, length = 50)
    private String name;

    @Column(length = 255)
    private String description;

    public AppRole(String name, String description) {
        this.name = normalizeRoleName(name);
        this.description = description;
    }

    private String normalizeRoleName(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Role name is required");
        }

        String normalized = value.trim().toUpperCase();

        if (normalized.startsWith("ROLE_")) {
            normalized = normalized.substring(5);
        }

        return normalized;
    }

    public String getSpringSecurityName() {
        return "ROLE_" + name;
    }
}