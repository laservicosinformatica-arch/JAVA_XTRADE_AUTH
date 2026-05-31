package com.xtrade.auth.xtrade_auth_server.internal.dto;

import java.util.Set;

public record InternalUpdateUserRolesRequest(Set<String> roles) {
}