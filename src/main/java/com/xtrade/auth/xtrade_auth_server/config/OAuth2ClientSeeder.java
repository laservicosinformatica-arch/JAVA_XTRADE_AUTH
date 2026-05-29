package com.xtrade.auth.xtrade_auth_server.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.UUID;

@Component
public class OAuth2ClientSeeder implements CommandLineRunner {

    private final RegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder passwordEncoder;

    public OAuth2ClientSeeder(
            RegisteredClientRepository registeredClientRepository,
            PasswordEncoder passwordEncoder
    ) {
        this.registeredClientRepository = registeredClientRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        createReactSpaClientIfNotExists();
        createPostmanClientIfNotExists();
        createServiceClientIfNotExists();
    }

    private void createReactSpaClientIfNotExists() {
        String clientId = "xtrade-client-spa";

        if (registeredClientRepository.findByClientId(clientId) != null) {
            return;
        }

        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)

                // SPA/browser não tem client_secret seguro.
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)

                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)

                .redirectUri("http://localhost:3000/callback")

                .postLogoutRedirectUri("http://localhost:3000")

                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("api.read")
                .scope("api.write")

                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())

                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                        .build())

                .build();

        registeredClientRepository.save(client);
    }

    private void createPostmanClientIfNotExists() {
        String clientId = "xtrade-client-postman";

        if (registeredClientRepository.findByClientId(clientId) != null) {
            return;
        }

        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)

                // Postman simulando SPA/login de usuário.
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)

                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)

                // Callback padrão do Postman.
                .redirectUri("https://oauth.pstmn.io/v1/callback")

                // Opcional, caso você teste com callback local.
                .redirectUri("http://localhost:3000/callback")

                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("api.read")
                .scope("api.write")

                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())

                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                        .build())

                .build();

        registeredClientRepository.save(client);
    }

    private void createServiceClientIfNotExists() {
        String clientId = "xtrade-client-service";

        if (registeredClientRepository.findByClientId(clientId) != null) {
            return;
        }

        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("xtrade-client-service")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUri("http://localhost:3000/callback")
                        .redirectUri("https://oauth.pstmn.io/v1/browser-callback")
                        .scope(OidcScopes.OPENID)
                        .scope(OidcScopes.PROFILE)
                        .clientSettings(ClientSettings.builder()
                                .requireProofKey(true)
                                .requireAuthorizationConsent(false)
                                .build())
                        .build();

        registeredClientRepository.save(client);
    }
}