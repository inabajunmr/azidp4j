package org.azidp4j.token.refreshtoken;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryRefreshTokenStore implements RefreshTokenStore {

    private static Map<String, RefreshToken> STORE = new ConcurrentHashMap<>();
    private static Map<String, RefreshToken> STORE_BY_AUTHORIZATION_CODE =
            new ConcurrentHashMap<>();

    @Override
    public synchronized void save(RefreshToken token) {
        STORE.put(token.token, token);
        if (token.authorizationCode != null) {
            STORE.put(token.token, token);
        }
    }

    @Override
    public synchronized RefreshToken consume(String token) {
        var rt = STORE.remove(token);
        if (rt == null) {
            return null;
        }
        if (rt.authorizationCode == null) {
            return rt;
        }
        return STORE_BY_AUTHORIZATION_CODE.remove(rt.authorizationCode);
    }

    @Override
    public synchronized RefreshToken removeByAuthorizationCode(String authorizationCode) {
        var rt = STORE_BY_AUTHORIZATION_CODE.remove(authorizationCode);
        if (rt == null) {
            return null;
        }
        return STORE.remove(rt.token);
    }
}
