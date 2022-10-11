package org.azidp4j.token.accesstoken;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryAccessTokenStore implements AccessTokenStore {

    /** Map<AccessTokenValue, AccessToken> */
    static Map<String, AccessToken> STORE = new ConcurrentHashMap<>();

    /** Map<AuthorizationCode, AccessToken> */
    static Map<String, AccessToken> STORE_BY_AUTHORIZATION_CODE = new ConcurrentHashMap<>();

    @Override
    public synchronized void save(AccessToken token) {
        STORE.put(token.getToken(), token);
        if (token.getAuthorizationCode() != null) {
            STORE_BY_AUTHORIZATION_CODE.put(token.getAuthorizationCode(), token);
        }
    }

    @Override
    public Optional<AccessToken> find(String token) {
        // TODO when token is null, return empty imediately
        return Optional.ofNullable(STORE.get(token));
    }

    @Override
    public synchronized void remove(String token) {
        var at = STORE.remove(token);
        if (at.getAuthorizationCode() == null) {
            return;
        }
        STORE_BY_AUTHORIZATION_CODE.remove(at.getAuthorizationCode());
    }

    @Override
    public synchronized void removeByAuthorizationCode(String code) {
        var at = STORE_BY_AUTHORIZATION_CODE.remove(code);
        STORE.remove(at.getToken());
    }
}
