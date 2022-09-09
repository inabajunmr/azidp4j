package org.azidp4j.authorize;

import java.util.Map;
import java.util.UUID;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.scope.ScopeValidator;
import org.azidp4j.token.accesstoken.AccessTokenIssuer;

public class Authorize {

    private final AuthorizationCodeStore authorizationCodeStore;
    private final ClientStore clientStore;

    private final AccessTokenIssuer accessTokenIssuer;

    private final AzIdPConfig azIdPConfig;

    private final ScopeValidator scopeValidator = new ScopeValidator();

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
            if (!scopeValidator.hasEnoughScope(authorizationRequest.scope, client)) {
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

            Integer maxAge = null;
            String nonce = null;
            if (scopeValidator.contains("openid", authorizationRequest.scope)) {
                // OIDC
                try {
                    maxAge = Integer.parseInt(authorizationRequest.maxAge);
                } catch (NumberFormatException e) {
                    return new AuthorizationResponse(
                            302,
                            Map.of(),
                            Map.of(
                                    "error",
                                    "invalid_request",
                                    "state",
                                    authorizationRequest.state));
                }
                nonce = authorizationRequest.nonce;
            }

            // issue authorization code
            var code = UUID.randomUUID().toString();
            authorizationCodeStore.save(
                    new AuthorizationCode(
                            authorizationRequest.sub,
                            code,
                            authorizationRequest.scope,
                            authorizationRequest.clientId,
                            authorizationRequest.state,
                            maxAge,
                            nonce));
            return new AuthorizationResponse(
                    302, Map.of("code", code, "state", authorizationRequest.state), Map.of());
        } else if (responseType == ResponseType.token) {
            if (!scopeValidator.hasEnoughScope(authorizationRequest.scope, client)) {
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
}
