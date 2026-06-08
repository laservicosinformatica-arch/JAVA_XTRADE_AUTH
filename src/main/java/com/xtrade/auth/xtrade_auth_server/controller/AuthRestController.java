package com.xtrade.auth.xtrade_auth_server.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.web.bind.annotation.*;

import com.xtrade.auth.xtrade_auth_server.model.dto.LoginRequest;
import com.xtrade.auth.xtrade_auth_server.model.dto.LoginResponse;
import com.xtrade.auth.xtrade_auth_server.service.AuthSecurityPolicyService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import java.time.Instant;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthRestController {

    private final AuthenticationManager authenticationManager;
    private final JwtEncoder jwtEncoder;
    private final AuthSecurityPolicyService securityPolicyService;

    @Value("${app.security.issuer}")
    private String issuer;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        securityPolicyService.prepareLogin(request.username());

        var authentication = authenticate(request);
        securityPolicyService.assertPasswordNotExpired(authentication.getName());
        securityPolicyService.recordSuccessfulLogin(authentication.getName());

        Instant now = Instant.now();
        int accessTokenTtlMinutes = securityPolicyService.getPolicy().getAccessTokenTtlMinutes();

        var roles = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> authority.startsWith("ROLE_"))
                .map(authority -> authority.substring(5))
                .distinct()
                .collect(Collectors.toList());

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(accessTokenTtlMinutes * 60L))
                .subject(authentication.getName())
                .claim("roles", roles)
                .claim("scope", "api.read api.write")
                .build();

        JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();

        String token = jwtEncoder.encode(
                JwtEncoderParameters.from(jwsHeader, claims)
        ).getTokenValue();

        return ResponseEntity.ok(new LoginResponse(token));
    }

    private org.springframework.security.core.Authentication authenticate(LoginRequest request) {
        try {
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.username(),
                            request.password()
                    )
            );
        } catch (BadCredentialsException ex) {
            securityPolicyService.recordFailedLogin(request.username());
            throw ex;
        }
    }
}
