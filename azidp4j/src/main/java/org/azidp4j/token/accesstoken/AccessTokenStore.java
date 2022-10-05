package org.azidp4j.token.accesstoken;

public interface AccessTokenStore {

    void save(InMemoryAccessToken token);

    InMemoryAccessToken find(String token);

    InMemoryAccessToken remove(String token);

    InMemoryAccessToken removeByAuthorizationCode(String code);
}
