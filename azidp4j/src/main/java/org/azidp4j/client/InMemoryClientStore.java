package org.azidp4j.client;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.azidp4j.token.TokenEndpointAuthMethod;

public class InMemoryClientStore implements ClientStore {

    private final Map<String, Client> STORE = new HashMap<>();

    public InMemoryClientStore() {
        STORE.put(
                "default",
                new Client(
                        "default",
                        "default",
                        Set.of(),
                        Set.of(GrantType.client_credentials),
                        Set.of(),
                        "default",
                        TokenEndpointAuthMethod.client_secret_basic));
    }

    @Override
    public void save(Client client) {
        STORE.put(client.clientId, client);
    }

    @Override
    public Client find(String clientId) {
        return STORE.get(clientId);
    }
}
