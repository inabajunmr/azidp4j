package org.azidp4j.token;

import java.util.Map;

public class TokenRequest {
    protected final String authenticatedClientId;
    protected final Long authTime;
    protected final Map<String, String> bodyParameters;

    public TokenRequest(String authenticatedClientId, Long authTime, Map<String, String> bodyParameters) {
        this.authenticatedClientId = authenticatedClientId;
        this.bodyParameters = bodyParameters;
        this.authTime = authTime;
    }
}
