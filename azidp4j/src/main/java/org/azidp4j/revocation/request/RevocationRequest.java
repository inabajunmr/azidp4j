package org.azidp4j.revocation.request;

import java.util.Map;

public class RevocationRequest {
    protected final String authenticatedClientId;
    protected final Map<String, Object> bodyParameters;

    public RevocationRequest(String authenticatedClientId, Map<String, Object> bodyParameters) {
        this.authenticatedClientId = authenticatedClientId;
        this.bodyParameters = bodyParameters;
    }
}
