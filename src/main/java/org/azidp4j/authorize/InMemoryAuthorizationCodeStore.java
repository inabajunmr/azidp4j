package org.azidp4j.authorize;

import java.util.HashMap;
import java.util.Map;

public class InMemoryAuthorizationCodeStore implements AuthorizationCodeStore {

    private static Map<String, AuthorizationCode> STORE = new HashMap<>();

    @Override
    public void save(AuthorizationCode code) {
        STORE.put(code.code, code);
    }

    @Override
    public AuthorizationCode find(String code) {
        return STORE.get(code);
    }
}
