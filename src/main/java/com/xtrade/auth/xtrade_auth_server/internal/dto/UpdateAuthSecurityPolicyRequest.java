package com.xtrade.auth.xtrade_auth_server.internal.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

public record UpdateAuthSecurityPolicyRequest(
        @Min(5) @Max(1440) int accessTokenTtlMinutes,
        @Min(1) @Max(20) int maxFailedLoginAttempts,
        @Min(1) @Max(10080) int lockDurationMinutes,
        @Min(0) @Max(3650) int passwordExpirationDays,
        @Min(8) @Max(128) int minimumPasswordLength,
        boolean requireUppercase,
        boolean requireLowercase,
        boolean requireNumber,
        boolean requireSpecialCharacter
) {
}
