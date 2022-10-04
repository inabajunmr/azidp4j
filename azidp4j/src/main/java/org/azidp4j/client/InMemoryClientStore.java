package org.azidp4j.client;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.azidp4j.token.TokenEndpointAuthMethod;

public class InMemoryClientStore implements ClientStore {

    private final Map<String, Client> STORE = new ConcurrentHashMap<>();

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
                        TokenEndpointAuthMethod.client_secret_basic,
                        Set.of(SigningAlgorithm.ES256)));
    }

    @Override
    public void save(Client client) {
        STORE.put(client.clientId, client);
    }

    @Override
    public Client find(String clientId) {
        return STORE.get(clientId);
    }

    @Override
    public Client delete(String clientId) {
        return STORE.remove(clientId);
    }
}
