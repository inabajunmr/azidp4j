package org.azidp4j.token.request;

import java.util.Map;

public class TokenRequest {
    /** Authenticated client identifier (not token request parameter) */
    protected final String authenticatedClientId;
    /** Token request body parameters. * */
    protected final Map<String, String> bodyParameters;

    public TokenRequest(String authenticatedClientId, Map<String, String> bodyParameters) {
        this.authenticatedClientId = authenticatedClientId;
        this.bodyParameters = bodyParameters;
    }
}
