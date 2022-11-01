package org.azidp4j.introspection.request;

import java.util.Map;

public class IntrospectionRequest {

    protected final Map<String, Object> bodyParameters;

    public IntrospectionRequest(Map<String, Object> bodyParameters) {
        this.bodyParameters = bodyParameters;
    }
}
