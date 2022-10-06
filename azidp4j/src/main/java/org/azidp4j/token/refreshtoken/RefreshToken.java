package org.azidp4j.token.refreshtoken;

public class RefreshToken {
    public final String token;
    public final String sub;
    public final String scope;
    public final String clientId;
    public final long expiresAtEpochSec;
    public final String authorizationCode;

    public RefreshToken(
            String token, String sub, String scope, String clientId, long expiresAtEpochSec) {
        this(token, sub, scope, clientId, expiresAtEpochSec, null);
    }

    public RefreshToken(
            String token,
            String sub,
            String scope,
            String clientId,
            long expiresAtEpochSec,
            String authorizationCode) {
        this.token = token;
        this.sub = sub;
        this.scope = scope;
        this.clientId = clientId;
        this.expiresAtEpochSec = expiresAtEpochSec;
        this.authorizationCode = authorizationCode;
    }
}
