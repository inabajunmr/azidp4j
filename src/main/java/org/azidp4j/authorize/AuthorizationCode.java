package org.azidp4j.authorize;

public class AuthorizationCode {

    /**
     * user identifier
     */
    final public String sub;

    final public String code;
    final public String scope;
    final public String clientId;

    final public String state;

    public AuthorizationCode(String sub, String code, String scope, String clientId, String state) {
        this.sub = sub;
        this.code = code;
        this.scope = scope;
        this.clientId = clientId;
        this.state = state;
    }
}
