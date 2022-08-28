package org.azidp4j.authorize;

import java.util.Map;

public class AuthorizationResponse {
    public Map<String, String> query;
    public Map<String, String> fragment;

    public AuthorizationResponse(Map<String, String> query, Map<String, String> fragment) {
        this.query = query;
        this.fragment = fragment;
    }
}
