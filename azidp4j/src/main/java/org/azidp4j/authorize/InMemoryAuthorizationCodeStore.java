package org.azidp4j.authorize;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryAuthorizationCodeStore implements AuthorizationCodeStore {

    private static Map<String, AuthorizationCode> STORE = new ConcurrentHashMap<>();

    @Override
    public void save(AuthorizationCode code) {
        STORE.put(code.code, code);
    }

    @Override
    public Optional<AuthorizationCode> consume(String code) {
        return Optional.ofNullable(STORE.remove(code));
    }
}
