package org.azidp4j.token.accesstoken.inmemory;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.azidp4j.token.accesstoken.AccessToken;

public class InMemoryAccessTokenStore {

    /** Map<AccessTokenValue, AccessToken> */
    static final Map<String, AccessToken> STORE = new ConcurrentHashMap<>();

    /** Map<AuthorizationCode, AccessToken> */
    static final Map<String, AccessToken> STORE_BY_AUTHORIZATION_CODE = new ConcurrentHashMap<>();

    public synchronized void save(AccessToken token) {
        STORE.put(token.getToken(), token);
        if (token.getAuthorizationCode() != null) {
            STORE_BY_AUTHORIZATION_CODE.put(token.getAuthorizationCode(), token);
        }
    }

    public Optional<AccessToken> find(String token) {
        return Optional.ofNullable(STORE.get(token));
    }

    public synchronized void remove(String token) {
        var at = STORE.remove(token);
        if (at.getAuthorizationCode() == null) {
            return;
        }
        STORE_BY_AUTHORIZATION_CODE.remove(at.getAuthorizationCode());
    }

    public synchronized void removeByAuthorizationCode(String code) {
        var at = STORE_BY_AUTHORIZATION_CODE.remove(code);
        STORE.remove(at.getToken());
    }
}
