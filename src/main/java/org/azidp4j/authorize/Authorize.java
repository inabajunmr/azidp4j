package org.azidp4j.authorize;

import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.token.AccessTokenIssuer;

public class Authorize {

    private final AuthorizationCodeStore authorizationCodeStore;
    private final ClientStore clientStore;

    private final AccessTokenIssuer accessTokenIssuer;

    private final AzIdPConfig azIdPConfig;

    public Authorize(
            ClientStore clientStore,
            AuthorizationCodeStore authorizationCodeStore,
            AccessTokenIssuer accessTokenIssuer,
            AzIdPConfig azIdPConfig) {
        this.clientStore = clientStore;
        this.authorizationCodeStore = authorizationCodeStore;
        this.accessTokenIssuer = accessTokenIssuer;
        this.azIdPConfig = azIdPConfig;
    }

    public AuthorizationResponse authorize(InternalAuthorizationRequest authorizationRequest) {
        var responseType = ResponseType.of(authorizationRequest.responseType);
        if (authorizationRequest.responseType == null) {
            return new AuthorizationResponse(400, Map.of(), Map.of());
        }

        // validate client
        if (authorizationRequest.clientId == null) {
            return new AuthorizationResponse(400, Map.of(), Map.of());
        }
        var client = clientStore.find(authorizationRequest.clientId);
        if (client == null) {
            return new AuthorizationResponse(400, Map.of(), Map.of());
        }

        // validate redirect urls
        if (authorizationRequest.redirectUri == null) {
            return new AuthorizationResponse(400, Map.of(), Map.of());
        }
        if (!client.redirectUris.contains(authorizationRequest.redirectUri)) {
            return new AuthorizationResponse(400, Map.of(), Map.of());
        }

        if (responseType == ResponseType.code) {
            // validate scope
            if (!hasEnoughScope(authorizationRequest.scope, client.scope)) {
                return new AuthorizationResponse(
                        302,
                        Map.of("error", "invalid_scope", "state", authorizationRequest.state),
                        Map.of());
            }

            // validate grant type and response type
            if (!client.grantTypes.contains(GrantType.authorization_code)) {
                return new AuthorizationResponse(
                        302,
                        Map.of("error", "unauthorized_client", "state", authorizationRequest.state),
                        Map.of());
            }
            if (!client.responseTypes.contains(ResponseType.code)) {
                return new AuthorizationResponse(
                        302,
                        Map.of(
                                "error",
                                "unsupported_response_type",
                                "state",
                                authorizationRequest.state),
                        Map.of());
            }

            // issue authorization code
            var code = UUID.randomUUID().toString();
            authorizationCodeStore.save(
                    new AuthorizationCode(
                            authorizationRequest.sub,
                            code,
                            authorizationRequest.scope,
                            authorizationRequest.clientId,
                            authorizationRequest.state));
            return new AuthorizationResponse(
                    302, Map.of("code", code, "state", authorizationRequest.state), Map.of());
        } else if (responseType == ResponseType.token) {
            if (!hasEnoughScope(authorizationRequest.scope, client.scope)) {
                return new AuthorizationResponse(
                        302,
                        Map.of(),
                        Map.of("error", "invalid_scope", "state", authorizationRequest.state));
            }

            // validate grant type and response type
            if (!client.grantTypes.contains(GrantType.implicit)) {
                return new AuthorizationResponse(
                        302,
                        Map.of(),
                        Map.of(
                                "error",
                                "unauthorized_client",
                                "state",
                                authorizationRequest.state));
            }
            if (!client.responseTypes.contains(ResponseType.token)) {
                return new AuthorizationResponse(
                        302,
                        Map.of(),
                        Map.of(
                                "error",
                                "unsupported_response_type",
                                "state",
                                authorizationRequest.state));
            }

            // issue access token
            var accessToken =
                    accessTokenIssuer.issue(
                            authorizationRequest.sub,
                            authorizationRequest.audiences,
                            authorizationRequest.clientId,
                            authorizationRequest.scope);
            return new AuthorizationResponse(
                    302,
                    Map.of(),
                    Map.of(
                            "access_token",
                            accessToken.serialize(),
                            "token_type",
                            "bearer",
                            "expires_in",
                            String.valueOf(azIdPConfig.accessTokenExpirationSec),
                            "scope",
                            authorizationRequest.scope,
                            "state",
                            authorizationRequest.state));
        }

        throw new AssertionError();
    }

    private boolean hasEnoughScope(String requestedScope, String clientRegisteredScope) {
        var requestedScopes = requestedScope.split(" ");
        var clientScopes =
                Arrays.stream(clientRegisteredScope.split(" ")).collect(Collectors.toSet());
        return requestedScopes.length
                == Arrays.stream(requestedScopes).filter(s -> clientScopes.contains(s)).count();
    }
}
