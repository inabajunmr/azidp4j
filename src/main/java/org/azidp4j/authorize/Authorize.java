package org.azidp4j.authorize;

import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;

public class Authorize {

    private final AuthorizationCodeStore authorizationCodeStore;
    private final ClientStore clientStore;

    public Authorize(ClientStore clientStore, AuthorizationCodeStore authorizationCodeStore) {
        this.clientStore = clientStore;
        this.authorizationCodeStore = authorizationCodeStore;
    }

    public AuthorizationResponse authorize(AuthorizationRequest authorizationRequest) {
        // TODO Unit test
        var responseType = ResponseType.of(authorizationRequest.responseType);
        if (authorizationRequest.responseType == null) {
            return new AuthorizationResponse(400, Map.of(), Map.of());
        }

        if (responseType == ResponseType.code) {
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

            // validate scope
            var requestedScopes = authorizationRequest.scope.split(" ");
            var clientScopes = Arrays.stream(client.scope.split(" ")).collect(Collectors.toSet());
            if (requestedScopes.length
                    != Arrays.stream(requestedScopes)
                            .filter(s -> clientScopes.contains(s))
                            .count()) {
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
        }

        throw new RuntimeException();
    }
}
