package org.azidp4j.token;

import org.azidp4j.authorize.AuthorizationCode;

import java.util.HashMap;
import java.util.Map;

public class InMemoryAccessTokenStore implements AccessTokenStore{

    private static Map<String, AccessToken> STORE = new HashMap<>();

    @Override
    public void save(AccessToken token) {
        STORE.put(token.accessToken, token);
    }

    @Override
    public AccessToken find(String token) {
        return STORE.get(token);
    }
}
