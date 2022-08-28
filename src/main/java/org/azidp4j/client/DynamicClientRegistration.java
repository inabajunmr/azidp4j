package org.azidp4j.client;

import java.util.Map;
import java.util.UUID;

public class DynamicClientRegistration {

    private final ClientStore clientStore;

    public DynamicClientRegistration(ClientStore clientStore) {
        this.clientStore = clientStore;
    }

    public ClientRegistrationResponse register(ClientRegistrationRequest request) {
        var clientId = UUID.randomUUID().toString();
        var clientSecret = UUID.randomUUID().toString();
        var client = new Client(clientId, clientSecret,
                request.redirectUris,
                request.grantTypes,
                request.responseTypes,
                request.scope);

        clientStore.save(client);

        return new ClientRegistrationResponse(
                Map.of("client_id", clientId,
                "client_secret", clientSecret,
                        "redirect_uris", request.redirectUris,
                        "grant_types", request.grantTypes,
                        "response_types", request.responseTypes,
                        "scope", request.scope));
    }
}
