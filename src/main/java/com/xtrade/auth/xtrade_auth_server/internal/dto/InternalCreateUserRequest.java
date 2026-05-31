package com.xtrade.auth.xtrade_auth_server.internal.dto;

import java.util.Set;

public record InternalCreateUserRequest(
        String username,
        String email,
        String fullName,
        String documentNumber,
        String password,
        Set<String> roles,
        boolean enabled
) {
}