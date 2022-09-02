package org.azidp4j.token;

import java.util.Map;
import java.util.Set;

public class TokenRequest {
    protected final String authenticatedClientId;
    protected final Set<String> audiences;
    protected final Map<String, String> bodyParameters;

    public TokenRequest(
            String authenticatedClientId,
            Set<String> audiences,
            Map<String, String> bodyParameters) {
        this.authenticatedClientId = authenticatedClientId;
        this.audiences = audiences;
        this.bodyParameters = bodyParameters;
    }
}
