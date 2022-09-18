package org.azidp4j.authorize;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class AuthorizationRequest {

    public final String authenticatedUserId;
    public final Set<String> consentedScope;
    protected final Map<String, String> queryParameters;

    public AuthorizationRequest(String authenticatedUserId, Map<String, String> queryParameters) {
        this.authenticatedUserId = authenticatedUserId;
        this.consentedScope = Set.of();
        this.queryParameters = queryParameters;
    }

    public AuthorizationRequest(
            String authenticatedUserId,
            Set<String> consentedScope,
            Map<String, String> queryParameters) {
        this.authenticatedUserId = authenticatedUserId;
        this.consentedScope = consentedScope;
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
            return new AuthorizationRequest(this.authenticatedUserId, noPrompt);
        } else {
            var queryParameterWithNewPrompt = new HashMap<>(queryParameters);
            queryParameterWithNewPrompt.put("prompt", String.join(" ", after));
            return new AuthorizationRequest(
                    this.authenticatedUserId, Map.copyOf(queryParameterWithNewPrompt));
        }
    }

    public Map<String, String> queryParameters() {
        return Map.copyOf(queryParameters);
    }
}
