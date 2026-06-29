package com.xtrade.auth.xtrade_auth_server.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.type.NumericBooleanConverter;

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

    @Column(name = "document_number", nullable = false, unique = true, length = 60)
    private String documentNumber;

    @Column(name = "full_name", length = 150)
    private String fullName;

    @Column(unique = true, length = 180)
    private String email;

    @Convert(converter = NumericBooleanConverter.class)
    @Column(nullable = false, columnDefinition = "NUMBER(1)")
    private boolean enabled = true;

    @Convert(converter = NumericBooleanConverter.class)
    @Column(name = "account_non_expired", nullable = false, columnDefinition = "NUMBER(1)")
    private boolean accountNonExpired = true;

    @Convert(converter = NumericBooleanConverter.class)
    @Column(name = "account_non_locked", nullable = false, columnDefinition = "NUMBER(1)")
    private boolean accountNonLocked = true;

    @Convert(converter = NumericBooleanConverter.class)
    @Column(name = "credentials_non_expired", nullable = false, columnDefinition = "NUMBER(1)")
    private boolean credentialsNonExpired = true;

    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts;

    @Column(name = "locked_at")
    private Instant lockedAt;

    @Column(name = "password_changed_at")
    private Instant passwordChangedAt = Instant.now();

    @Column(name = "active_session_id", length = 80)
    private String activeSessionId;

    @Column(name = "active_session_issued_at")
    private Instant activeSessionIssuedAt;

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
            String documentNumber,
            String fullName,
            String email,
            Set<AppRole> roles
    ) {
        this.username = username.trim().toLowerCase();
        this.passwordHash = passwordHash;
        this.documentNumber = documentNumber;
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
        this.lockedAt = Instant.now();
        this.updatedAt = Instant.now();
    }

    public void unlock() {
        this.accountNonLocked = true;
        this.lockedAt = null;
        this.failedLoginAttempts = 0;
        this.updatedAt = Instant.now();
    }

    public void recordFailedLogin() {
        this.failedLoginAttempts++;
        this.updatedAt = Instant.now();
    }

    public void recordSuccessfulLogin() {
        this.failedLoginAttempts = 0;
        this.lockedAt = null;
        this.updatedAt = Instant.now();
    }

    public void startSession(String sessionId) {
        this.activeSessionId = sessionId;
        this.activeSessionIssuedAt = Instant.now();
        this.updatedAt = Instant.now();
    }

    public boolean isActiveSession(String sessionId) {
        return sessionId != null && sessionId.equals(activeSessionId);
    }

    public void changePassword(String encodedPassword) {
        this.passwordHash = encodedPassword;
        this.passwordChangedAt = Instant.now();
        this.credentialsNonExpired = true;
        this.updatedAt = Instant.now();
    }
}
