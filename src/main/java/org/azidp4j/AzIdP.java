package org.azidp4j;

import com.nimbusds.jose.JOSEException;
import org.azidp4j.authorize.*;
import org.azidp4j.jwt.jwks.JWKSupplier;
import org.azidp4j.token.*;

public class AzIdP {

    private final JWKSupplier jwkSupplier;
    AuthorizationCodeStore authorizationCodeStore = new InMemoryAuthorizationCodeStore();
    Authorize authorize = new Authorize(authorizationCodeStore);
    AccessTokenStore accessTokenStore = new InMemoryAccessTokenStore();
    IssueToken issueToken;

    public AzIdP(JWKSupplier jwkSupplier) {
        this.jwkSupplier = jwkSupplier;
        this.issueToken = new IssueToken(authorizationCodeStore, accessTokenStore, jwkSupplier);
    }

    public AuthorizationResponse authorize(AuthorizationRequest authorizationRequest) {
        return authorize.authorize(authorizationRequest);
    }

    public TokenResponse issueToken(TokenRequest tokenRequest) {
        return issueToken.issue(tokenRequest);
    }
}
