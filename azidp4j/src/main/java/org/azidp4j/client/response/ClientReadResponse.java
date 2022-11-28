package org.azidp4j.client.response;

import java.util.Map;

public class ClientReadResponse {

    public final int status;

    public final Map<String, Object> body;

    public ClientReadResponse(int status, Map<String, Object> body) {
        this.status = status;
        this.body = body;
    }
}
