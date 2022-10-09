package org.azidp4j.token.accesstoken;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryAccessTokenStore implements AccessTokenStore {

    /** Map<AccessTokenValue, AccessToken> */
    static Map<String, InMemoryAccessToken> STORE = new ConcurrentHashMap<>();

    /** Map<AuthorizationCode, AccessToken> */
    static Map<String, InMemoryAccessToken> STORE_BY_AUTHORIZATION_CODE = new ConcurrentHashMap<>();

    @Override
    public synchronized void save(InMemoryAccessToken token) {
        STORE.put(token.getToken(), token);
        if (token.getAuthorizationCode() != null) {
            STORE_BY_AUTHORIZATION_CODE.put(token.getAuthorizationCode(), token);
        }
    }

    @Override
    public Optional<InMemoryAccessToken> find(String token) {
        return Optional.ofNullable(STORE.get(token));
    }

    @Override
    public synchronized InMemoryAccessToken remove(String token) {
        var at = STORE.remove(token);
        if (at.getAuthorizationCode() == null) {
            return at;
        }
        return STORE_BY_AUTHORIZATION_CODE.remove(at.getAuthorizationCode());
    }

    @Override
    public synchronized InMemoryAccessToken removeByAuthorizationCode(String code) {
        var at = STORE_BY_AUTHORIZATION_CODE.remove(code);
        return STORE.remove(at.getToken());
    }
}
