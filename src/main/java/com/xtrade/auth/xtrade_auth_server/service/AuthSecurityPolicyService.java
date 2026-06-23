package com.xtrade.auth.xtrade_auth_server.service;

import com.xtrade.auth.xtrade_auth_server.entity.AppUser;
import com.xtrade.auth.xtrade_auth_server.entity.AuthSecurityPolicy;
import com.xtrade.auth.xtrade_auth_server.internal.dto.UpdateAuthSecurityPolicyRequest;
import com.xtrade.auth.xtrade_auth_server.repository.AppUserRepository;
import com.xtrade.auth.xtrade_auth_server.repository.AuthSecurityPolicyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthSecurityPolicyService {

    private final AuthSecurityPolicyRepository policyRepository;
    private final AppUserRepository appUserRepository;

    @Transactional
    public AuthSecurityPolicy getPolicy() {
        return policyRepository.findFirstByOrderByIdAsc()
                .orElseGet(() -> policyRepository.save(new AuthSecurityPolicy()));
    }

    @Transactional
    public AuthSecurityPolicy updatePolicy(UpdateAuthSecurityPolicyRequest request) {
        AuthSecurityPolicy policy = getPolicy();
        policy.setAccessTokenTtlMinutes(request.accessTokenTtlMinutes());
        policy.setMaxFailedLoginAttempts(request.maxFailedLoginAttempts());
        policy.setLockDurationMinutes(request.lockDurationMinutes());
        policy.setPasswordExpirationDays(request.passwordExpirationDays());
        policy.setMinimumPasswordLength(request.minimumPasswordLength());
        policy.setRequireUppercase(request.requireUppercase());
        policy.setRequireLowercase(request.requireLowercase());
        policy.setRequireNumber(request.requireNumber());
        policy.setRequireSpecialCharacter(request.requireSpecialCharacter());
        policy.setUpdatedAt(Instant.now());
        return policyRepository.save(policy);
    }

    @Transactional
    public void prepareLogin(String username) {
        AppUser user = appUserRepository.findByUsernameIgnoreCase(username).orElse(null);
        if (user == null || user.isAccountNonLocked() || user.getLockedAt() == null) {
            return;
        }

        AuthSecurityPolicy policy = getPolicy();
        Instant unlockAt = user.getLockedAt().plus(policy.getLockDurationMinutes(), java.time.temporal.ChronoUnit.MINUTES);
        if (!Instant.now().isBefore(unlockAt)) {
            user.unlock();
            appUserRepository.save(user);
        }
    }

    @Transactional
    public void recordFailedLogin(String username) {
        appUserRepository.findByUsernameIgnoreCase(username).ifPresent(user -> {
            user.recordFailedLogin();
            if (user.getFailedLoginAttempts() >= getPolicy().getMaxFailedLoginAttempts()) {
                user.lock();
            }
            appUserRepository.save(user);
        });
    }

    @Transactional
    public void recordSuccessfulLogin(String username) {
        appUserRepository.findByUsernameIgnoreCase(username).ifPresent(user -> {
            user.recordSuccessfulLogin();
            appUserRepository.save(user);
        });
    }

    @Transactional
    public String startSingleUserSession(String username) {
        AppUser user = appUserRepository.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials."));
        String sessionId = UUID.randomUUID().toString();
        user.startSession(sessionId);
        appUserRepository.save(user);
        return sessionId;
    }

    @Transactional(readOnly = true)
    public boolean isActiveSession(String username, String sessionId) {
        return appUserRepository.findByUsernameIgnoreCase(username)
                .map(user -> user.isEnabled() && user.isAccountNonLocked() && user.isActiveSession(sessionId))
                .orElse(false);
    }

    @Transactional(readOnly = true)
    public void assertPasswordNotExpired(String username) {
        AuthSecurityPolicy policy = policyRepository.findFirstByOrderByIdAsc()
                .orElseGet(AuthSecurityPolicy::new);
        if (policy.getPasswordExpirationDays() == 0) {
            return;
        }

        AppUser user = appUserRepository.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials."));
        Instant changedAt = user.getPasswordChangedAt() == null ? user.getCreatedAt() : user.getPasswordChangedAt();
        if (Duration.between(changedAt, Instant.now()).toDays() >= policy.getPasswordExpirationDays()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Password expired. Contact an administrator.");
        }
    }

    @Transactional(readOnly = true)
    public void validatePassword(String password) {
        AuthSecurityPolicy policy = policyRepository.findFirstByOrderByIdAsc()
                .orElseGet(AuthSecurityPolicy::new);

        if (password == null || password.length() < policy.getMinimumPasswordLength()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Password must have at least " + policy.getMinimumPasswordLength() + " characters."
            );
        }
        if (policy.isRequireUppercase() && password.chars().noneMatch(Character::isUpperCase)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password must contain an uppercase letter.");
        }
        if (policy.isRequireLowercase() && password.chars().noneMatch(Character::isLowerCase)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password must contain a lowercase letter.");
        }
        if (policy.isRequireNumber() && password.chars().noneMatch(Character::isDigit)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password must contain a number.");
        }
        if (policy.isRequireSpecialCharacter() && password.chars().allMatch(Character::isLetterOrDigit)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password must contain a special character.");
        }
    }
}
