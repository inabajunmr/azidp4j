package org.azidp4j.authorize;

public class AuthorizationCode {
    final public String code;
    final public String scope;
    final public String clientId;

    final public String state;

    public AuthorizationCode(String code, String scope, String clientId, String state) {
        this.code = code;
        this.scope = scope;
        this.clientId = clientId;
        this.state = state;
    }
}
