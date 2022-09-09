package org.azidp4j.authorize;

public class AuthorizationCode {

    /** user identifier */
    public final String sub;

    public final String code;
    public final String scope;
    public final String clientId;
    public final Integer maxAge;
    public final String nonce;
    public final String state;

    public AuthorizationCode(
            String sub,
            String code,
            String scope,
            String clientId,
            String state,
            Integer maxAge,
            String nonce) {
        this.sub = sub;
        this.code = code;
        this.scope = scope;
        this.clientId = clientId;
        this.state = state;
        this.maxAge = maxAge;
        this.nonce = nonce;
    }

    public AuthorizationCode(String sub, String code, String scope, String clientId, String state) {
        this.sub = sub;
        this.code = code;
        this.scope = scope;
        this.clientId = clientId;
        this.state = state;
        this.maxAge = null;
        this.nonce = null;
    }
}
