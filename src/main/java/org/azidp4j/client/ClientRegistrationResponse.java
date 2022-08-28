package org.azidp4j.client;

import java.util.Map;

public class ClientRegistrationResponse {
    public final Map<String, Object> body;

    public ClientRegistrationResponse(Map<String, Object> body) {
        this.body = body;
    }
}
