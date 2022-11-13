package org.azidp4j.client;

import java.util.Optional;

public interface ClientStore {

    /**
     * Persist client.
     *
     * @param client registration target
     */
    void save(Client client);

    /**
     * Find persisted client.
     *
     * @param clientId client identifier
     * @return client
     */
    Optional<Client> find(String clientId);

    /**
     * Remove persisted client.
     *
     * @param clientId client identifier.
     * @return client
     */
    Optional<Client> remove(String clientId);
}
