package org.azidp4j.token;

import java.util.Map;

public class TokenRequest {
    /** Authenticated client identifier (not token request parameter) */
    protected final String authenticatedClientId;
    /** Time when the End-User authentication occurred (not token request parameter) */
    protected final Long authTime;
    /** Token request body parameters. * */
    protected final Map<String, String> bodyParameters;

    public TokenRequest(
            String authenticatedClientId, Long authTime, Map<String, String> bodyParameters) {
        this.authenticatedClientId = authenticatedClientId;
        this.bodyParameters = bodyParameters;
        this.authTime = authTime;
    }
}
