package org.azidp4j;

import org.azidp4j.authorize.AuthorizationRequest;
import org.azidp4j.authorize.AuthorizationResponse;
import org.azidp4j.authorize.Authorize;
import org.azidp4j.token.IssueToken;
import org.azidp4j.token.TokenRequest;
import org.azidp4j.token.TokenResponse;

public class AzIdP {
    Authorize authorize = new Authorize();
    public AuthorizationResponse authorize(AuthorizationRequest authorizationRequest) {
        return authorize.authorize(authorizationRequest);
    }

    IssueToken issueToken = new IssueToken();
    public TokenResponse issueToken(TokenRequest tokenRequest) {
        return issueToken.issue(tokenRequest);
    }
}
