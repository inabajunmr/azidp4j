package org.azidp4j.token.refreshtoken;

import java.util.Map;
import java.util.Optional;
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
    public Optional<RefreshToken> find(String token) {
        return Optional.ofNullable(STORE.remove(token));
    }

    @Override
    public synchronized Optional<RefreshToken> consume(String token) {
        var rt = STORE.remove(token);
        if (rt == null) {
            return Optional.empty();
        }
        if (rt.authorizationCode == null) {
            return Optional.of(rt);
        }
        return Optional.ofNullable(STORE_BY_AUTHORIZATION_CODE.remove(rt.authorizationCode));
    }

    @Override
    public synchronized void removeByAuthorizationCode(String authorizationCode) {
        var rt = STORE_BY_AUTHORIZATION_CODE.remove(authorizationCode);
        if (rt == null) {
            return;
        }
        STORE.remove(rt.token);
    }
}
