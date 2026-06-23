package com.xtrade.auth.xtrade_auth_server.internal.dto;

import jakarta.validation.constraints.NotBlank;

public record InternalSessionValidationRequest(
        @NotBlank String username,
        @NotBlank String sessionId
) {}
