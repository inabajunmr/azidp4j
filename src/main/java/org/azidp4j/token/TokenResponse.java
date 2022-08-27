package org.azidp4j.token;

import java.util.Map;

public class TokenResponse {

    public Map<String, Object> body;

    public TokenResponse(Map<String, Object> body) {
        this.body = body;
    }
}
