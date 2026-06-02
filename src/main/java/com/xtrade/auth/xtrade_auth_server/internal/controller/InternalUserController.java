package com.xtrade.auth.xtrade_auth_server.internal.controller;


import com.xtrade.auth.xtrade_auth_server.entity.AppRole;
import com.xtrade.auth.xtrade_auth_server.entity.AppUser;
import com.xtrade.auth.xtrade_auth_server.internal.dto.InternalCreateUserRequest;
import com.xtrade.auth.xtrade_auth_server.internal.dto.InternalUpdateUserRolesRequest;
import com.xtrade.auth.xtrade_auth_server.internal.dto.InternalUserResponse;
import com.xtrade.auth.xtrade_auth_server.repository.AppRoleRepository;
import com.xtrade.auth.xtrade_auth_server.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import com.xtrade.auth.xtrade_auth_server.internal.dto.InternalUpdateUserRequest;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
@RequestMapping("/internal/users")
public class InternalUserController {

    private static final String INTERNAL_API_KEY_HEADER = "X-Internal-Api-Key";

    private final AppUserRepository appUserRepository;
    private final AppRoleRepository appRoleRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.internal-api-key}")
    private String internalApiKey;

    @GetMapping
    public ResponseEntity<List<InternalUserResponse>> findAll(
            @RequestHeader(INTERNAL_API_KEY_HEADER) String apiKey
    ) {
        assertInternalKey(apiKey);

        return ResponseEntity.ok(
                appUserRepository.findAll()
                        .stream()
                        .map(InternalUserResponse::from)
                        .toList()
        );
    }

    @PutMapping("/{username}")
    public ResponseEntity<InternalUserResponse> update(
            @RequestHeader(INTERNAL_API_KEY_HEADER) String apiKey,
            @PathVariable String username,
            @RequestBody InternalUpdateUserRequest request
    ) {
        assertInternalKey(apiKey);

        AppUser user = appUserRepository.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found."));

        if (request.email() != null && !request.email().equalsIgnoreCase(user.getEmail())
                && appUserRepository.existsByEmailIgnoreCase(request.email())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists.");
        }

        if (request.documentNumber() != null && !request.documentNumber().equals(user.getDocumentNumber())
                && appUserRepository.existsByDocumentNumber(request.documentNumber())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Document already exists.");
        }

        user.setEmail(request.email() == null ? null : request.email().trim().toLowerCase());
        user.setFullName(request.fullName());
        user.setDocumentNumber(request.documentNumber());
        user.setEnabled(request.enabled());
        user.setAccountNonLocked(request.accountNonLocked());
        user.setUpdatedAt(Instant.now());

        if (request.password() != null && !request.password().isBlank()) {
            user.setPasswordHash(passwordEncoder.encode(request.password()));
        }

        user.getRoles().clear();
        user.getRoles().addAll(resolveRoles(request.roles()));

        return ResponseEntity.ok(InternalUserResponse.from(appUserRepository.save(user)));
    }
    @PostMapping
    public ResponseEntity<InternalUserResponse> create(
            @RequestHeader(INTERNAL_API_KEY_HEADER) String apiKey,
            @RequestBody InternalCreateUserRequest request
    ) {
        assertInternalKey(apiKey);

        if (appUserRepository.existsByUsernameIgnoreCase(request.username())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already exists.");
        }

        if (appUserRepository.existsByDocumentNumber(request.documentNumber())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Document already exists.");
        }

        if (request.email() != null && appUserRepository.existsByEmailIgnoreCase(request.email())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists.");
        }

        AppUser user = new AppUser(
                request.username(),
                passwordEncoder.encode(request.password()),
                request.documentNumber(),
                request.fullName(),
                request.email(),
                resolveRoles(request.roles())
        );

        user.setEnabled(request.enabled());

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(InternalUserResponse.from(appUserRepository.save(user)));
    }

    @PatchMapping("/{username}/enable")
    public ResponseEntity<InternalUserResponse> enable(
            @RequestHeader(INTERNAL_API_KEY_HEADER) String apiKey,
            @PathVariable String username
    ) {
        assertInternalKey(apiKey);

        AppUser user = appUserRepository.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found."));

        user.enable();

        return ResponseEntity.ok(InternalUserResponse.from(appUserRepository.save(user)));
    }
    
    @PatchMapping("/{username}/roles")
    public ResponseEntity<InternalUserResponse> updateRoles(
            @RequestHeader(INTERNAL_API_KEY_HEADER) String apiKey,
            @PathVariable String username,
            @RequestBody InternalUpdateUserRolesRequest request
    ) {
        assertInternalKey(apiKey);

        AppUser user = appUserRepository.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found."));

        user.getRoles().clear();
        user.getRoles().addAll(resolveRoles(request.roles()));
        user.enable();

        return ResponseEntity.ok(InternalUserResponse.from(appUserRepository.save(user)));
    }

    @PatchMapping("/{username}/disable")
    public ResponseEntity<Void> disable(
            @RequestHeader(INTERNAL_API_KEY_HEADER) String apiKey,
            @PathVariable String username
    ) {
        assertInternalKey(apiKey);

        AppUser user = appUserRepository.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found."));

        user.disable();
        appUserRepository.save(user);

        return ResponseEntity.noContent().build();
    }

    private Set<AppRole> resolveRoles(Set<String> roles) {
        if (roles == null || roles.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one role is required.");
        }

        return roles.stream()
                .map(this::normalizeRole)
                .map(role -> appRoleRepository.findByName(role)
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Role not found: " + role)))
                .collect(Collectors.toSet());
    }

    private String normalizeRole(String role) {
        String normalized = role.trim().toUpperCase();
        return normalized.startsWith("ROLE_") ? normalized.substring(5) : normalized;
    }

    private void assertInternalKey(String apiKey) {
        if (apiKey == null || !apiKey.equals(internalApiKey)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid internal API key.");
        }
    }
}