package org.azidp4j.authorize;

public class AuthorizationCode {
    final public String code;
    final public String scope;
    final public String clientId;

    public AuthorizationCode(String code, String scope, String clientId) {
        this.code = code;
        this.scope = scope;
        this.clientId = clientId;
    }
}
