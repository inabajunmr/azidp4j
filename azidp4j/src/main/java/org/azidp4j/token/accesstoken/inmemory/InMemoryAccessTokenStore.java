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
        STORE.put(token.token, token);
        if (token.authorizationCode != null) {
            STORE_BY_AUTHORIZATION_CODE.put(token.authorizationCode, token);
        }
    }

    public Optional<AccessToken> find(String token) {
        return Optional.ofNullable(STORE.get(token));
    }

    public synchronized void remove(String token) {
        var at = STORE.remove(token);
        if (at.authorizationCode == null) {
            return;
        }
        STORE_BY_AUTHORIZATION_CODE.remove(at.authorizationCode);
    }

    public synchronized void removeByAuthorizationCode(String code) {
        var at = STORE_BY_AUTHORIZATION_CODE.remove(code);
        STORE.remove(at.token);
    }
}
