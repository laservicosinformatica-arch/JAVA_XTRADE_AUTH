package com.xtrade.auth.xtrade_auth_server.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Entity
@Data
@NoArgsConstructor
@Table(name = "app_users")
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Pode ser login, username ou email.
     */
    @Column(nullable = false, unique = true, length = 80)
    private String username;

    /**
     * BCrypt hash.
     */
    @Column(name = "password_hash", nullable = false, length = 120)
    private String passwordHash;

    /**
     * CPF somente com números.
     */
    @Column(nullable = false, unique = true, length = 11)
    private String cpf;

    @Column(name = "full_name", length = 150)
    private String fullName;

    @Column(unique = true, length = 180)
    private String email;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "account_non_expired", nullable = false)
    private boolean accountNonExpired = true;

    @Column(name = "account_non_locked", nullable = false)
    private boolean accountNonLocked = true;

    @Column(name = "credentials_non_expired", nullable = false)
    private boolean credentialsNonExpired = true;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at")
    private Instant updatedAt;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "app_user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<AppRole> roles = new HashSet<>();

    public AppUser(
            String username,
            String passwordHash,
            String cpf,
            String fullName,
            String email,
            Set<AppRole> roles
    ) {
        this.username = username.trim().toLowerCase();
        this.passwordHash = passwordHash;
        this.cpf = cpf;
        this.fullName = fullName;
        this.email = email == null ? null : email.trim().toLowerCase();

        if (roles != null) {
            this.roles.addAll(roles);
        }
    }

    public void disable() {
        this.enabled = false;
        this.updatedAt = Instant.now();
    }

    public void enable() {
        this.enabled = true;
        this.updatedAt = Instant.now();
    }

    public void lock() {
        this.accountNonLocked = false;
        this.updatedAt = Instant.now();
    }

    public void unlock() {
        this.accountNonLocked = true;
        this.updatedAt = Instant.now();
    }
}