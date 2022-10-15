package org.azidp4j.token;

import java.util.Map;

public class TokenResponse {

    public final int status;
    public final Map<String, Object> body;

    public TokenResponse(int status, Map<String, Object> body) {
        this.status = status;
        this.body = body;
    }
}
