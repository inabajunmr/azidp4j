package org.azidp4j.authorize.request;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class AuthorizationRequest {

    /**
     * Authenticated user identifier (not authorization request parameter)
     *
     * <p>The value is used as ID Token sub claim.
     */
    public final String authenticatedUserSubject;
    /** User consented scope (not authorization request parameter) */
    public final Set<String> consentedScope;
    /** Time when the End-User authentication occurred (not authorization request parameter) */
    public final Long authTime;
    /** Authorization request query parameters. * */
    public final Map<String, String> queryParameters;
    /** authentication context class. */
    public String authenticatedUserAcr;

    /**
     * Authorization request.
     *
     * @param authenticatedUserSubject authenticated user who send authorization request. If no user
     *     authenticated, specify null. The value will be `sub` claim.
     * @param authTime Last user authenticated time. If no user authenticated, specify null.
     * @param consentedScope Last user authenticated time. If no user authenticated, specify null.
     * @param queryParameters Authorization request query parameters map.
     */
    public AuthorizationRequest(
            String authenticatedUserSubject,
            Long authTime,
            Set<String> consentedScope,
            Map<String, String> queryParameters) {
        this.authenticatedUserSubject = authenticatedUserSubject;
        this.authTime = authTime;
        this.consentedScope = consentedScope;
        this.queryParameters = queryParameters;
    }

    /**
     * Clone AuthorizationRequest without specific prompt parameter.
     *
     * @param target removable target like `login`.
     * @return cloned AuthorizationRequest
     */
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
            return new AuthorizationRequest(
                    this.authenticatedUserSubject, this.authTime, consentedScope, noPrompt);
        } else {
            var queryParameterWithNewPrompt = new HashMap<>(queryParameters);
            queryParameterWithNewPrompt.put("prompt", String.join(" ", after));
            return new AuthorizationRequest(
                    this.authenticatedUserSubject,
                    this.authTime,
                    consentedScope,
                    Map.copyOf(queryParameterWithNewPrompt));
        }
    }

    /**
     * Return query parameters.
     *
     * @return query parameters
     */
    public Map<String, String> queryParameters() {
        return Map.copyOf(queryParameters);
    }

    public void setAuthenticatedUserAcr(String authenticatedUserAcr) {
        this.authenticatedUserAcr = authenticatedUserAcr;
    }
}
