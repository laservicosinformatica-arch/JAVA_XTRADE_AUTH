package com.xtrade.auth.xtrade_auth_server.internal.dto;

import com.xtrade.auth.xtrade_auth_server.entity.AppRole;
import com.xtrade.auth.xtrade_auth_server.entity.AppUser;

import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;

public record InternalUserResponse(
        Long id,
        String username,
        String email,
        String fullName,
        String documentNumber,
        Set<String> roles,
        boolean enabled,
        boolean accountNonLocked,
        Instant createdAt,
        Instant updatedAt
) {
    public static InternalUserResponse from(AppUser user) {
        return new InternalUserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getFullName(),
                user.getDocumentNumber(),
                user.getRoles().stream()
                        .map(AppRole::getName)
                        .collect(Collectors.toSet()),
                user.isEnabled(),
                user.isAccountNonLocked(),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }
}