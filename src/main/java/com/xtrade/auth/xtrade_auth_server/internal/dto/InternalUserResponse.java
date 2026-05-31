package com.xtrade.auth.xtrade_auth_server.internal.dto;

import java.util.Set;
import java.util.stream.Collectors;

import com.xtrade.auth.xtrade_auth_server.entity.AppRole;
import com.xtrade.auth.xtrade_auth_server.entity.AppUser;

public record InternalUserResponse(
        Long id,
        String username,
        String email,
        String fullName,
        Set<String> roles,
        boolean enabled
) {
    public static InternalUserResponse from(AppUser user) {
        return new InternalUserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getFullName(),
                user.getRoles().stream().map(AppRole::getName).collect(Collectors.toSet()),
                user.isEnabled()
        );
    }
}