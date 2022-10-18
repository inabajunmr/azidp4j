package org.azidp4j.client.response;

import java.util.Map;

public class ClientDeleteResponse {

    public final int status;

    public final Map<String, Object> body;

    public ClientDeleteResponse(int status, Map<String, Object> body) {
        this.status = status;
        this.body = body;
    }
}
