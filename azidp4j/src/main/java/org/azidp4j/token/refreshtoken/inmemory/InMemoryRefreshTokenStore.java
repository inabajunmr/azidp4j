package org.azidp4j.token.refreshtoken.inmemory;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.azidp4j.token.refreshtoken.RefreshToken;

public class InMemoryRefreshTokenStore {

    private static final Map<String, RefreshToken> STORE = new ConcurrentHashMap<>();
    private static final Map<String, RefreshToken> STORE_BY_AUTHORIZATION_CODE =
            new ConcurrentHashMap<>();

    public synchronized void save(RefreshToken token) {
        STORE.put(token.token, token);
        if (token.authorizationCode != null) {
            STORE_BY_AUTHORIZATION_CODE.put(token.authorizationCode, token);
        }
    }

    public Optional<RefreshToken> find(String token) {
        return Optional.ofNullable(STORE.remove(token));
    }

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

    public synchronized void removeByAuthorizationCode(String authorizationCode) {
        var rt = STORE_BY_AUTHORIZATION_CODE.remove(authorizationCode);
        if (rt == null) {
            return;
        }
        STORE.remove(rt.token);
    }
}
