package org.azidp4j.authorize;

import java.util.Map;
import java.util.Set;

public class AuthorizationRequest {

    public final String userId;
    protected final Set<String> audiences;
    protected final Map<String, String> queryParameters;

    public AuthorizationRequest(
            String userId, Set<String> audiences, Map<String, String> queryParameters) {
        this.userId = userId;
        this.audiences = audiences;
        this.queryParameters = queryParameters;
    }
}
