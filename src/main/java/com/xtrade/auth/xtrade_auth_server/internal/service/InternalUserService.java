package com.xtrade.auth.xtrade_auth_server.internal.service;

import com.xtrade.auth.xtrade_auth_server.entity.AppRole;
import com.xtrade.auth.xtrade_auth_server.entity.AppUser;
import com.xtrade.auth.xtrade_auth_server.internal.dto.InternalCreateUserRequest;
import com.xtrade.auth.xtrade_auth_server.internal.dto.InternalUpdateUserRequest;
import com.xtrade.auth.xtrade_auth_server.internal.dto.InternalUpdateUserRolesRequest;
import com.xtrade.auth.xtrade_auth_server.internal.dto.InternalUserResponse;
import com.xtrade.auth.xtrade_auth_server.repository.AppRoleRepository;
import com.xtrade.auth.xtrade_auth_server.repository.AppUserRepository;
import com.xtrade.auth.xtrade_auth_server.service.AuthSecurityPolicyService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class InternalUserService {

    private final AppUserRepository appUserRepository;
    private final AppRoleRepository appRoleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthSecurityPolicyService securityPolicyService;

    @Transactional(readOnly = true)
    public List<InternalUserResponse> findAll() {
        return appUserRepository.findAll().stream()
                .map(InternalUserResponse::from)
                .toList();
    }

    @Transactional
    public InternalUserResponse update(String username, InternalUpdateUserRequest request) {
        AppUser user = findUser(username);

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
        if (request.accountNonLocked()) {
            user.unlock();
        } else {
            user.lock();
        }

        if (request.password() != null && !request.password().isBlank()) {
            securityPolicyService.validatePassword(request.password());
            user.changePassword(passwordEncoder.encode(request.password()));
        }

        user.getRoles().clear();
        user.getRoles().addAll(resolveRoles(request.roles()));
        user.setUpdatedAt(Instant.now());
        return InternalUserResponse.from(appUserRepository.save(user));
    }

    @Transactional
    public InternalUserResponse create(InternalCreateUserRequest request) {
        if (appUserRepository.existsByUsernameIgnoreCase(request.username())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already exists.");
        }
        if (appUserRepository.existsByDocumentNumber(request.documentNumber())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Document already exists.");
        }
        if (request.email() != null && appUserRepository.existsByEmailIgnoreCase(request.email())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists.");
        }

        securityPolicyService.validatePassword(request.password());
        AppUser user = new AppUser(
                request.username(),
                passwordEncoder.encode(request.password()),
                request.documentNumber(),
                request.fullName(),
                request.email(),
                resolveRoles(request.roles())
        );
        user.setEnabled(request.enabled());
        user.setPasswordChangedAt(Instant.now());
        return InternalUserResponse.from(appUserRepository.save(user));
    }

    @Transactional
    public InternalUserResponse enable(String username) {
        AppUser user = findUser(username);
        user.enable();
        return InternalUserResponse.from(appUserRepository.save(user));
    }

    @Transactional
    public InternalUserResponse updateRoles(String username, InternalUpdateUserRolesRequest request) {
        AppUser user = findUser(username);
        user.getRoles().clear();
        user.getRoles().addAll(resolveRoles(request.roles()));
        user.enable();
        return InternalUserResponse.from(appUserRepository.save(user));
    }

    @Transactional
    public void disable(String username) {
        AppUser user = findUser(username);
        user.disable();
        appUserRepository.save(user);
    }

    private AppUser findUser(String username) {
        return appUserRepository.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found."));
    }

    private Set<AppRole> resolveRoles(Set<String> roles) {
        if (roles == null || roles.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one role is required.");
        }

        return roles.stream()
                .map(this::normalizeRole)
                .map(role -> appRoleRepository.findByName(role)
                        .orElseThrow(() -> new ResponseStatusException(
                                HttpStatus.BAD_REQUEST,
                                "Role not found: " + role
                        )))
                .collect(Collectors.toSet());
    }

    private String normalizeRole(String role) {
        String normalized = role.trim().toUpperCase();
        return normalized.startsWith("ROLE_") ? normalized.substring(5) : normalized;
    }
}
