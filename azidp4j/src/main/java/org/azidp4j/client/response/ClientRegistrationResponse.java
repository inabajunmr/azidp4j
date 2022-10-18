package org.azidp4j.client.response;

import java.util.Map;

public class ClientRegistrationResponse {

    public final int status;

    public final Map<String, Object> body;

    public ClientRegistrationResponse(int status, Map<String, Object> body) {
        this.status = status;
        this.body = body;
    }
}
