package org.azidp4j.token.accesstoken;

import java.time.Instant;
import java.util.Set;

public class AccessToken {
    private final String token;
    private final String sub;
    private final String scope;
    private final String clientId;
    private final Set<String> audience;
    private final long expiresAtEpochSec;
    private final long issuedAtEpochSec;
    private final String authorizationCode;

    public String getToken() {
        return token;
    }

    public String getSub() {
        return sub;
    }

    public String getScope() {
        return scope;
    }

    public String getClientId() {
        return clientId;
    }

    public Set<String> getAudience() {
        return audience;
    }

    public long getExpiresAtEpochSec() {
        return expiresAtEpochSec;
    }

    public long getIssuedAtEpochSec() {
        return issuedAtEpochSec;
    }

    public String getAuthorizationCode() {
        return authorizationCode;
    }

    public boolean expired() {
        return this.getExpiresAtEpochSec() < Instant.now().getEpochSecond();
    }

    public AccessToken(
            String token,
            String sub,
            String scope,
            String clientId,
            Set<String> audience,
            long expiresAtEpochSec,
            long issuedAtEpochSec,
            String authorizationCode) {
        this.token = token;
        this.sub = sub;
        this.scope = scope;
        this.clientId = clientId;
        this.audience = audience;
        this.expiresAtEpochSec = expiresAtEpochSec;
        this.issuedAtEpochSec = issuedAtEpochSec;
        this.authorizationCode = authorizationCode;
    }

    public AccessToken(
            String token,
            String sub,
            String scope,
            String clientId,
            Set<String> audience,
            long expiresAtEpochSec,
            long issuedAtEpochSec) {
        this(token, sub, scope, clientId, audience, expiresAtEpochSec, issuedAtEpochSec, null);
    }
}
