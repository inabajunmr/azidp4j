package org.azidp4j.authorize;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class AuthorizationRequest {

    /** Authenticated user identifier (not authorization request parameter) */
    public final String authenticatedUserId;
    /** User consented scope (not authorization request parameter) */
    public final Set<String> consentedScope;
    /** Time when the End-User authentication occurred (not authorization request parameter) */
    public final Long authTime;
    /** Authorization request query parameters. * */
    protected final Map<String, String> queryParameters;

    public AuthorizationRequest(
            String authenticatedUserId, Long authTime, Map<String, String> queryParameters) {
        this.authenticatedUserId = authenticatedUserId;
        this.authTime = authTime;
        this.consentedScope = Set.of();
        this.queryParameters = queryParameters;
    }

    public AuthorizationRequest(
            String authenticatedUserId,
            Long authTime,
            Set<String> consentedScope,
            Map<String, String> queryParameters) {
        this.authenticatedUserId = authenticatedUserId;
        this.authTime = authTime;
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
            return new AuthorizationRequest(this.authenticatedUserId, this.authTime, noPrompt);
        } else {
            var queryParameterWithNewPrompt = new HashMap<>(queryParameters);
            queryParameterWithNewPrompt.put("prompt", String.join(" ", after));
            return new AuthorizationRequest(
                    this.authenticatedUserId,
                    this.authTime,
                    Map.copyOf(queryParameterWithNewPrompt));
        }
    }

    public Map<String, String> queryParameters() {
        return Map.copyOf(queryParameters);
    }
}
