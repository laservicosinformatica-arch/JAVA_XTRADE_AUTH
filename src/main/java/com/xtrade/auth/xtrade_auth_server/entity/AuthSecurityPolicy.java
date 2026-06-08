package com.xtrade.auth.xtrade_auth_server.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Entity
@NoArgsConstructor
@Table(name = "auth_security_policy")
public class AuthSecurityPolicy {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "access_token_ttl_minutes", nullable = false)
    private int accessTokenTtlMinutes = 30;

    @Column(name = "max_failed_login_attempts", nullable = false)
    private int maxFailedLoginAttempts = 5;

    @Column(name = "lock_duration_minutes", nullable = false)
    private int lockDurationMinutes = 30;

    @Column(name = "password_expiration_days", nullable = false)
    private int passwordExpirationDays = 90;

    @Column(name = "minimum_password_length", nullable = false)
    private int minimumPasswordLength = 10;

    @Column(name = "require_uppercase", nullable = false)
    private boolean requireUppercase = true;

    @Column(name = "require_lowercase", nullable = false)
    private boolean requireLowercase = true;

    @Column(name = "require_number", nullable = false)
    private boolean requireNumber = true;

    @Column(name = "require_special_character", nullable = false)
    private boolean requireSpecialCharacter = true;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();
}
