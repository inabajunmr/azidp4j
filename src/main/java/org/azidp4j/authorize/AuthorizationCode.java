package org.azidp4j.authorize;

public class AuthorizationCode {

    /** user identifier */
    public final String sub;

    public final String code;
    public final String scope;
    public final String clientId;
    public final String redirectUri;
    public final Long authTime;
    public final String nonce;
    public final String state;

    public AuthorizationCode(
            String sub,
            String code,
            String scope,
            String clientId,
            String redirectUri,
            String state,
            Long authTime,
            String nonce) {
        this.sub = sub;
        this.code = code;
        this.scope = scope;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.state = state;
        this.authTime = authTime;
        this.nonce = nonce;
    }

    public AuthorizationCode(
            String sub,
            String code,
            String scope,
            String clientId,
            String redirectUri,
            String state) {
        this.sub = sub;
        this.code = code;
        this.scope = scope;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.state = state;
        this.authTime = null;
        this.nonce = null;
    }
}
