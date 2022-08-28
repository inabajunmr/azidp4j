package org.azidp4j.client;

public interface ClientStore {

    void save(Client client);

    Client find(String clientId);
}
