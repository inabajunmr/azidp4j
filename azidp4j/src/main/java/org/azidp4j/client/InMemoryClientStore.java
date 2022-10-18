package org.azidp4j.client;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

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
                        SigningAlgorithm.ES256));
    }

    @Override
    public void save(Client client) {
        STORE.put(client.clientId, client);
    }

    @Override
    public Optional<Client> find(String clientId) {
        return Optional.ofNullable(STORE.get(clientId));
    }

    @Override
    public Optional<Client> remove(String clientId) {
        return Optional.ofNullable(STORE.remove(clientId));
    }
}
