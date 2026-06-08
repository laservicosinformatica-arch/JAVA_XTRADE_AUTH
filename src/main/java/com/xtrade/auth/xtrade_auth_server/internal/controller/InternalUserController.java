package com.xtrade.auth.xtrade_auth_server.internal.controller;

import com.xtrade.auth.xtrade_auth_server.internal.dto.InternalCreateUserRequest;
import com.xtrade.auth.xtrade_auth_server.internal.dto.InternalUpdateUserRequest;
import com.xtrade.auth.xtrade_auth_server.internal.dto.InternalUpdateUserRolesRequest;
import com.xtrade.auth.xtrade_auth_server.internal.dto.InternalUserResponse;
import com.xtrade.auth.xtrade_auth_server.internal.service.InternalUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/internal/users")
public class InternalUserController {

    private static final String INTERNAL_API_KEY_HEADER = "X-Internal-Api-Key";

    private final InternalUserService internalUserService;

    @Value("${app.internal-api-key}")
    private String internalApiKey;

    @GetMapping
    public ResponseEntity<List<InternalUserResponse>> findAll(
            @RequestHeader(INTERNAL_API_KEY_HEADER) String apiKey
    ) {
        assertInternalKey(apiKey);
        return ResponseEntity.ok(internalUserService.findAll());
    }

    @PutMapping("/{username}")
    public ResponseEntity<InternalUserResponse> update(
            @RequestHeader(INTERNAL_API_KEY_HEADER) String apiKey,
            @PathVariable String username,
            @RequestBody InternalUpdateUserRequest request
    ) {
        assertInternalKey(apiKey);
        return ResponseEntity.ok(internalUserService.update(username, request));
    }

    @PostMapping
    public ResponseEntity<InternalUserResponse> create(
            @RequestHeader(INTERNAL_API_KEY_HEADER) String apiKey,
            @RequestBody InternalCreateUserRequest request
    ) {
        assertInternalKey(apiKey);
        return ResponseEntity.status(HttpStatus.CREATED).body(internalUserService.create(request));
    }

    @PatchMapping("/{username}/enable")
    public ResponseEntity<InternalUserResponse> enable(
            @RequestHeader(INTERNAL_API_KEY_HEADER) String apiKey,
            @PathVariable String username
    ) {
        assertInternalKey(apiKey);
        return ResponseEntity.ok(internalUserService.enable(username));
    }

    @PatchMapping("/{username}/roles")
    public ResponseEntity<InternalUserResponse> updateRoles(
            @RequestHeader(INTERNAL_API_KEY_HEADER) String apiKey,
            @PathVariable String username,
            @RequestBody InternalUpdateUserRolesRequest request
    ) {
        assertInternalKey(apiKey);
        return ResponseEntity.ok(internalUserService.updateRoles(username, request));
    }

    @PatchMapping("/{username}/disable")
    public ResponseEntity<Void> disable(
            @RequestHeader(INTERNAL_API_KEY_HEADER) String apiKey,
            @PathVariable String username
    ) {
        assertInternalKey(apiKey);
        internalUserService.disable(username);
        return ResponseEntity.noContent().build();
    }

    private void assertInternalKey(String apiKey) {
        if (apiKey == null || !apiKey.equals(internalApiKey)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid internal API key.");
        }
    }
}
