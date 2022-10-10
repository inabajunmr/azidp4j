package org.azidp4j.introspection;

import java.util.Map;

public class IntrospectionResponse {

    public int status;
    public Map<String, Object> body;

    public IntrospectionResponse(int status, Map<String, Object> body) {
        this.status = status;
        this.body = body;
    }
}
