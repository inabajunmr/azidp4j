package org.azidp4j.client;

import java.util.Optional;

public interface ClientStore {

    void save(Client client);

    Optional<Client> find(String clientId);

    Optional<Client> remove(String clientId);
}
