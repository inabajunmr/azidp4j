package org.azidp4j.springsecuritysample.claims;

import java.util.Map;
import java.util.Optional;

public class ClaimsParameters {
    private final Map<String, ClaimsParameter> idToken;
    private final Map<String, ClaimsParameter> userInfo;

    public ClaimsParameters(
            Map<String, ClaimsParameter> idToken, Map<String, ClaimsParameter> userInfo) {
        this.idToken = idToken;
        this.userInfo = userInfo;
    }

    public Optional<ClaimsParameter> fromIdToken(String claimName) {
        if (idToken == null) {
            Optional.empty();
        }
        if (!idToken.containsKey(claimName)) {
            return Optional.empty();
        }
        return Optional.of(idToken.get(claimName));
    }
}
