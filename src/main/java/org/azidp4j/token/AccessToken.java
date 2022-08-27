package org.azidp4j.token;

public class AccessToken {

    public final String accessToken;

    public final String scope;

    public AccessToken(String accessToken, String scope) {
        this.accessToken = accessToken;
        this.scope = scope;
    }
}
