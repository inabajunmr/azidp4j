package org.azidp4j.client;

public interface ClientValidator {

    /**
     * Validate client for client registration.
     *
     * <p>If IdP can't allow some type of client, implements the class and throw Exception against
     * unallowable client.
     *
     * @param client Client will be registered
     * @throws IllegalArgumentException
     */
    void validate(Client client);
}
