package org.azidp4j.client.request;

import java.util.Map;

public class ClientRequest {

    protected final Map<String, Object> bodyParameters;

    public ClientRequest(Map<String, Object> bodyParameters) {
        this.bodyParameters = bodyParameters;
    }
}
