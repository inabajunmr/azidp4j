package org.azidp4j.authorize;

import java.util.Map;
import java.util.stream.Collectors;

public class AuthorizationRequest {

    public final String userId;
    protected final Map<String, String> queryParameters;

    /** before user authentication */
    public AuthorizationRequest(Map<String, String> queryParameters) {
        this.userId = null;
        this.queryParameters = queryParameters;
    }

    public AuthorizationRequest(String userId, Map<String, String> queryParameters) {
        this.userId = userId;
        this.queryParameters = queryParameters;
    }

    public AuthorizationRequest noPrompt() {
        var noPrompt =
                queryParameters.entrySet().stream()
                        .filter(kv -> !kv.getKey().equals("prompt"))
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        return new AuthorizationRequest(this.userId, noPrompt);
    }

    public Map<String, String> queryParameters() {
        return Map.copyOf(queryParameters);
    }
}
