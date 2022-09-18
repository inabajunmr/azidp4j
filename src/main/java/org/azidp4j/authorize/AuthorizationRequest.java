package org.azidp4j.authorize;

import java.util.Arrays;
import java.util.HashMap;
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

    public AuthorizationRequest removePrompt(String target) {
        var prompt = queryParameters.get("prompt");
        if (prompt == null) {
            return this;
        }
        var after =
                Arrays.stream(prompt.split(" "))
                        .filter(v -> !v.equals(target))
                        .collect(Collectors.toSet());
        if (after.isEmpty()) {
            // remove whole prompt parameter with key
            var noPrompt =
                    queryParameters.entrySet().stream()
                            .filter(kv -> !kv.getKey().equals("prompt"))
                            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            return new AuthorizationRequest(this.userId, noPrompt);
        } else {
            var queryParameterWithNewPrompt = new HashMap<>(queryParameters);
            queryParameterWithNewPrompt.put("prompt", String.join(" ", after));
            return new AuthorizationRequest(this.userId, Map.copyOf(queryParameterWithNewPrompt));
        }
    }

    public Map<String, String> queryParameters() {
        return Map.copyOf(queryParameters);
    }
}
