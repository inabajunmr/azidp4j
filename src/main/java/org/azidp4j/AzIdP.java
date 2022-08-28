package org.azidp4j;

import com.nimbusds.jose.jwk.JWKSet;
import org.azidp4j.authorize.*;
import org.azidp4j.token.*;

public class AzIdP {

    AuthorizationCodeStore authorizationCodeStore = new InMemoryAuthorizationCodeStore();
    Authorize authorize = new Authorize(authorizationCodeStore);
    AccessTokenStore accessTokenStore = new InMemoryAccessTokenStore();
    IssueToken issueToken;

    public AzIdP(AzIdPConfig azIdPConfig, JWKSet jwkSet) {
        this.issueToken = new IssueToken(azIdPConfig, jwkSet, authorizationCodeStore, accessTokenStore);
    }

    public AuthorizationResponse authorize(AuthorizationRequest authorizationRequest) {
        return authorize.authorize(authorizationRequest);
    }

    public TokenResponse issueToken(TokenRequest tokenRequest) {
        return issueToken.issue(tokenRequest);
    }
}
