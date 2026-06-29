package com.xtrade.auth.xtrade_auth_server.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Convert;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.type.NumericBooleanConverter;

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

    @Convert(converter = NumericBooleanConverter.class)
    @Column(name = "require_uppercase", nullable = false, columnDefinition = "NUMBER(1)")
    private boolean requireUppercase = true;

    @Convert(converter = NumericBooleanConverter.class)
    @Column(name = "require_lowercase", nullable = false, columnDefinition = "NUMBER(1)")
    private boolean requireLowercase = true;

    @Convert(converter = NumericBooleanConverter.class)
    @Column(name = "require_number", nullable = false, columnDefinition = "NUMBER(1)")
    private boolean requireNumber = true;

    @Convert(converter = NumericBooleanConverter.class)
    @Column(name = "require_special_character", nullable = false, columnDefinition = "NUMBER(1)")
    private boolean requireSpecialCharacter = true;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();
}
