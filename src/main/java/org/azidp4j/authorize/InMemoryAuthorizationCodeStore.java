package org.azidp4j.authorize;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryAuthorizationCodeStore implements AuthorizationCodeStore {

    private static Map<String, AuthorizationCode> STORE = new ConcurrentHashMap<>();

    @Override
    public void save(AuthorizationCode code) {
        STORE.put(code.code, code);
    }

    @Override
    public AuthorizationCode consume(String code) {
        return STORE.remove(code);
    }
}
