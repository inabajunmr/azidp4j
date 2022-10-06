package org.azidp4j.token.accesstoken;

import java.util.Set;

public class InMemoryAccessToken implements AccessToken {
    private final String token;
    private final String sub;
    private final String scope;
    private final String clientId;
    private final Set<String> audience;
    private final long expiresAtEpochSec;
    private final String authorizationCode;

    @Override
    public String getToken() {
        return token;
    }

    @Override
    public String getSub() {
        return sub;
    }

    @Override
    public String getScope() {
        return scope;
    }

    @Override
    public String getClientId() {
        return clientId;
    }

    @Override
    public Set<String> getAudience() {
        return audience;
    }

    @Override
    public long getExpiresAtEpochSec() {
        return expiresAtEpochSec;
    }

    @Override
    public String getAuthorizationCode() {
        return authorizationCode;
    }

    public InMemoryAccessToken(
            String token,
            String sub,
            String scope,
            String clientId,
            Set<String> audience,
            long expiresAtEpochSec,
            String authorizationCode) {
        this.token = token;
        this.sub = sub;
        this.scope = scope;
        this.clientId = clientId;
        this.audience = audience;
        this.expiresAtEpochSec = expiresAtEpochSec;
        this.authorizationCode = authorizationCode;
    }

    public InMemoryAccessToken(
            String token,
            String sub,
            String scope,
            String clientId,
            Set<String> audience,
            long expiresAtEpochSec) {
        this(token, sub, scope, clientId, audience, expiresAtEpochSec, null);
    }
}
