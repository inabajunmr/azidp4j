package org.azidp4j;

import org.azidp4j.authorize.*;
import org.azidp4j.token.*;

public class AzIdP {

    AuthorizationCodeStore authorizationCodeStore = new InMemoryAuthorizationCodeStore();
    Authorize authorize = new Authorize(authorizationCodeStore);
    public AuthorizationResponse authorize(AuthorizationRequest authorizationRequest) {
        return authorize.authorize(authorizationRequest);
    }

    AccessTokenStore accessTokenStore = new InMemoryAccessTokenStore();
    IssueToken issueToken = new IssueToken(authorizationCodeStore, accessTokenStore);
    public TokenResponse issueToken(TokenRequest tokenRequest) {
        return issueToken.issue(tokenRequest);
    }
}
