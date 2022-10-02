package org.azidp4j.client;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.azidp4j.authorize.ResponseType;
import org.azidp4j.token.TokenEndpointAuthMethod;
import org.azidp4j.util.MapUtil;

public class DynamicClientRegistration {

    private final ClientStore clientStore;

    public DynamicClientRegistration(ClientStore clientStore) {
        this.clientStore = clientStore;
    }

    public ClientRegistrationResponse register(ClientRegistrationRequest request) {

        Set<GrantType> grantTypes = new HashSet<>();
        if (request.grantTypes == null) {
            // default
            grantTypes.add(GrantType.authorization_code);
        } else {
            for (String g : request.grantTypes) {
                var grantType = GrantType.of(g);
                if (grantType == null) {
                    return new ClientRegistrationResponse(
                            400, Map.of("error", "invalid_grant_type"));
                }
                grantTypes.add(grantType);
            }
        }

        Set<ResponseType> responseTypes = new HashSet<>();
        if (request.responseTypes == null) {
            // default
            responseTypes.add(ResponseType.code);
        } else {
            for (String r : request.responseTypes) {
                var responseType = ResponseType.of(r);
                if (responseType == null) {
                    return new ClientRegistrationResponse(
                            400, Map.of("error", "invalid_response_type"));
                }
                responseTypes.add(responseType);
            }
        }

        TokenEndpointAuthMethod tokenEndpointAuthMethod =
                TokenEndpointAuthMethod.client_secret_basic;
        if (request.tokenEndpointAuthMethod != null) {
            var tam = TokenEndpointAuthMethod.of(request.tokenEndpointAuthMethod);
            if (tam == null) {
                return new ClientRegistrationResponse(
                        400, Map.of("error", "invalid_token_endpoint_auth_method"));
            }
            tokenEndpointAuthMethod = tam;
        }

        var client =
                new Client(
                        UUID.randomUUID().toString(),
                        tokenEndpointAuthMethod != TokenEndpointAuthMethod.none
                                ? UUID.randomUUID().toString()
                                : null,
                        request.redirectUris != null ? request.redirectUris : Set.of(),
                        grantTypes,
                        responseTypes,
                        request.scope,
                        tokenEndpointAuthMethod);
        clientStore.save(client);
        return new ClientRegistrationResponse(
                201,
                MapUtil.nullRemovedMap(
                        "client_id",
                        client.clientId,
                        "client_secret",
                        client.clientSecret,
                        "redirect_uris",
                        client.redirectUris,
                        "grant_types",
                        client.grantTypes.stream().map(Enum::name).collect(Collectors.toSet()),
                        "response_types",
                        client.responseTypes.stream().map(Enum::name).collect(Collectors.toSet()),
                        "scope",
                        client.scope,
                        "token_endpoint_auth_method",
                        client.tokenEndpointAuthMethod.name()));
    }
}
