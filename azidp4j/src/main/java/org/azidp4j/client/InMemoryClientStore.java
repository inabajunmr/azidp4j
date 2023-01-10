package org.azidp4j.client;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.azidp4j.util.HumanReadable;

public class InMemoryClientStore implements ClientStore {

    private final Map<String, Client> STORE = new ConcurrentHashMap<>();

    public InMemoryClientStore() {
        STORE.put(
                "default",
                new Client(
                        "default",
                        "default",
                        Set.of(),
                        Set.of(),
                        ApplicationType.WEB,
                        Set.of(GrantType.client_credentials),
                        new HumanReadable<>("client_name", "default", null),
                        null,
                        null,
                        "default",
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        TokenEndpointAuthMethod.client_secret_basic,
                        null,
                        TokenEndpointAuthMethod.client_secret_basic,
                        null,
                        TokenEndpointAuthMethod.client_secret_basic,
                        null,
                        SigningAlgorithm.ES256,
                        null,
                        false,
                        List.of("acr1"),
                        null));
    }

    @Override
    public void save(Client client) {
        STORE.put(client.clientId, client);
    }

    @Override
    public Optional<Client> find(String clientId) {
        if (clientId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(STORE.get(clientId));
    }

    @Override
    public Optional<Client> remove(String clientId) {
        if (clientId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(STORE.remove(clientId));
    }
}
