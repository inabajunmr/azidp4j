package org.azidp4j.client;

import java.util.Set;
import java.util.UUID;
import org.azidp4j.authorize.ResponseType;
import org.azidp4j.token.TokenEndpointAuthMethod;
import org.azidp4j.util.MapUtil;

public class DynamicClientRegistration {

    private final ClientStore clientStore;

    public DynamicClientRegistration(ClientStore clientStore) {
        this.clientStore = clientStore;
    }

    public ClientRegistrationResponse register(ClientRegistrationRequest request) {
        var grantTypes =
                request.grantTypes != null
                        ? request.grantTypes
                        : Set.of(GrantType.authorization_code);
        var responseTypes =
                request.responseTypes != null ? request.responseTypes : Set.of(ResponseType.code);
        var client =
                new Client(
                        UUID.randomUUID().toString(),
                        request.tokenEndpointAuthMethod != TokenEndpointAuthMethod.none
                                ? UUID.randomUUID().toString()
                                : null,
                        request.redirectUris,
                        grantTypes,
                        responseTypes,
                        request.scope,
                        request.tokenEndpointAuthMethod);
        clientStore.save(client);
        return new ClientRegistrationResponse(
                MapUtil.nullRemovedMap(
                        "client_id",
                        client.clientId,
                        "client_secret",
                        client.clientSecret,
                        "redirect_uris",
                        request.redirectUris,
                        "grant_types",
                        request.grantTypes,
                        "response_types",
                        request.responseTypes,
                        "scope",
                        request.scope,
                        "token_endpoint_auth_method",
                        request.tokenEndpointAuthMethod));
    }
}
