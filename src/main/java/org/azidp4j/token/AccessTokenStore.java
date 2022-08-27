package org.azidp4j.token;

public interface AccessTokenStore {

    void save(AccessToken token);

    AccessToken find(String token);
}
