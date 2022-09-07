package org.azidp4j.token;

import java.util.Map;

public class TokenRequest {
    protected final String authenticatedClientId;
    protected final Map<String, String> bodyParameters;

    public TokenRequest(String authenticatedClientId, Map<String, String> bodyParameters) {
        this.authenticatedClientId = authenticatedClientId;
        this.bodyParameters = bodyParameters;
    }
}
