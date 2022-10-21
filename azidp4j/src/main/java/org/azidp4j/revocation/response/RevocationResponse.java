package org.azidp4j.revocation.response;

import java.util.Map;

public class RevocationResponse {

    public final int status;
    public final Map<String, Object> body;

    public RevocationResponse(int status, Map<String, Object> body) {
        this.status = status;
        this.body = body;
    }
}
