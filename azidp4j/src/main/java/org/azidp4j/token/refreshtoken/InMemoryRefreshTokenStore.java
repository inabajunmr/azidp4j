package org.azidp4j.token.refreshtoken;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryRefreshTokenStore implements RefreshTokenStore {

    private static Map<String, RefreshToken> STORE = new ConcurrentHashMap<>();

    @Override
    public void save(RefreshToken token) {
        STORE.put(token.token, token);
    }

    @Override
    public RefreshToken consume(String token) {
        return STORE.remove(token);
    }
}
