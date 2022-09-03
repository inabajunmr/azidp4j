package org.azidp4j.authorize;

import java.util.Map;

public class AuthorizationRequest {

    public final String userId;
    protected final Map<String, String> queryParameters;

    public AuthorizationRequest(String userId, Map<String, String> queryParameters) {
        this.userId = userId;
        this.queryParameters = queryParameters;
    }
}
