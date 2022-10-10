package org.azidp4j.introspection;

import java.util.Map;

public class IntrospectionRequest {

    protected final Map<String, String> bodyParameters;

    public IntrospectionRequest(Map<String, String> bodyParameters) {
        this.bodyParameters = bodyParameters;
    }
}
