package com.xtrade.auth.xtrade_auth_server.internal.controller;

import com.xtrade.auth.xtrade_auth_server.internal.dto.AuthSecurityPolicyResponse;
import com.xtrade.auth.xtrade_auth_server.internal.dto.UpdateAuthSecurityPolicyRequest;
import com.xtrade.auth.xtrade_auth_server.service.AuthSecurityPolicyService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/internal/auth-security-policy")
public class InternalAuthSecurityPolicyController {

    private static final String INTERNAL_API_KEY_HEADER = "X-Internal-Api-Key";

    private final AuthSecurityPolicyService securityPolicyService;

    @Value("${app.internal-api-key}")
    private String internalApiKey;

    @GetMapping
    public ResponseEntity<AuthSecurityPolicyResponse> get(
            @RequestHeader(INTERNAL_API_KEY_HEADER) String apiKey
    ) {
        assertInternalKey(apiKey);
        return ResponseEntity.ok(AuthSecurityPolicyResponse.from(securityPolicyService.getPolicy()));
    }

    @PutMapping
    public ResponseEntity<AuthSecurityPolicyResponse> update(
            @RequestHeader(INTERNAL_API_KEY_HEADER) String apiKey,
            @Valid @RequestBody UpdateAuthSecurityPolicyRequest request
    ) {
        assertInternalKey(apiKey);
        return ResponseEntity.ok(AuthSecurityPolicyResponse.from(securityPolicyService.updatePolicy(request)));
    }

    private void assertInternalKey(String apiKey) {
        if (apiKey == null || !apiKey.equals(internalApiKey)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid internal API key.");
        }
    }
}
