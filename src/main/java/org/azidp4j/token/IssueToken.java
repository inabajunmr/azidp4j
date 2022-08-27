package org.azidp4j.token;

import org.azidp4j.authorize.AuthorizationCode;
import org.azidp4j.authorize.AuthorizationCodeStore;

import java.util.Map;
import java.util.UUID;

public class IssueToken {

    AuthorizationCodeStore authorizationCodeStore;
    AccessTokenStore accessTokenStore;

    public IssueToken(AuthorizationCodeStore authorizationCodeStore, AccessTokenStore accessTokenStore) {
        this.authorizationCodeStore = authorizationCodeStore;
        this.accessTokenStore = accessTokenStore;
    }

    public TokenResponse issue(TokenRequest request) {
        var authorizationCode = authorizationCodeStore.find(request.code);
        var accessToken =  new AccessToken(UUID.randomUUID().toString(), authorizationCode.scope);
        accessTokenStore.save(accessToken);
        return new TokenResponse(Map.of("access_token", accessToken.accessToken,
                "token_type", "bearer",
                "expires_in",3600,
                "scope", accessToken.scope,
                "state", authorizationCode.state));
    }
}
