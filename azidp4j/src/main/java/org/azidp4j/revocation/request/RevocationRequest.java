package org.azidp4j.revocation.request;

import java.util.Map;

public class RevocationRequest {
    protected final String authenticatedClientId;
    protected final Map<String, String> bodyParameters;

    public RevocationRequest(String authenticatedClientId, Map<String, String> bodyParameters) {
        this.authenticatedClientId = authenticatedClientId;
        this.bodyParameters = bodyParameters;
    }
}
