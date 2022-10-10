package org.azidp4j.token.refreshtoken;

import java.time.Instant;
import java.util.Set;

public class RefreshToken {
    public final String token;
    public final String sub;
    public final String scope;
    public final String clientId;
    public final Set<String> audience;
    public final long expiresAtEpochSec;
    public final long issuedAtEpochSec;
    public final String authorizationCode;

    public RefreshToken(
            String token,
            String sub,
            String scope,
            String clientId,
            Set<String> audience,
            long expiresAtEpochSec,
            long issuedAtEpochSec) {
        this(token, sub, scope, clientId, audience, expiresAtEpochSec, issuedAtEpochSec, null);
    }

    public RefreshToken(
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

    public boolean expired() {
        return this.expiresAtEpochSec < Instant.now().getEpochSecond();
    }
}
