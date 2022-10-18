package org.azidp4j.authorize.authorizationcode.inmemory;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.azidp4j.authorize.authorizationcode.AuthorizationCode;

public class InMemoryAuthorizationCodeStore {

    private static final Map<String, AuthorizationCode> STORE = new ConcurrentHashMap<>();

    public void save(AuthorizationCode code) {
        STORE.put(code.code, code);
    }

    public Optional<AuthorizationCode> consume(String code) {
        return Optional.ofNullable(STORE.remove(code));
    }
}
