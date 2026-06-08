package com.xtrade.auth.xtrade_auth_server.internal.dto;

import com.xtrade.auth.xtrade_auth_server.entity.AuthSecurityPolicy;

import java.time.Instant;

public record AuthSecurityPolicyResponse(
        int accessTokenTtlMinutes,
        int maxFailedLoginAttempts,
        int lockDurationMinutes,
        int passwordExpirationDays,
        int minimumPasswordLength,
        boolean requireUppercase,
        boolean requireLowercase,
        boolean requireNumber,
        boolean requireSpecialCharacter,
        Instant updatedAt
) {
    public static AuthSecurityPolicyResponse from(AuthSecurityPolicy policy) {
        return new AuthSecurityPolicyResponse(
                policy.getAccessTokenTtlMinutes(),
                policy.getMaxFailedLoginAttempts(),
                policy.getLockDurationMinutes(),
                policy.getPasswordExpirationDays(),
                policy.getMinimumPasswordLength(),
                policy.isRequireUppercase(),
                policy.isRequireLowercase(),
                policy.isRequireNumber(),
                policy.isRequireSpecialCharacter(),
                policy.getUpdatedAt()
        );
    }
}
