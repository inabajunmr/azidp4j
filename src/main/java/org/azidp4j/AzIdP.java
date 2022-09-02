package org.azidp4j;

import com.nimbusds.jose.jwk.JWKSet;
import org.azidp4j.authorize.*;
import org.azidp4j.client.ClientRegistrationRequest;
import org.azidp4j.client.ClientRegistrationResponse;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.DynamicClientRegistration;
import org.azidp4j.token.*;

public class AzIdP {

    AuthorizationCodeStore authorizationCodeStore = new InMemoryAuthorizationCodeStore();
    Authorize authorize;
    AuthorizationRequestParser authorizationRequestParser = new AuthorizationRequestParser();
    AccessTokenStore accessTokenStore = new InMemoryAccessTokenStore();
    IssueToken issueToken;
    DynamicClientRegistration clientRegistration;

    public AzIdP(AzIdPConfig azIdPConfig, JWKSet jwkSet, ClientStore clientStore) {
        var accessTokenIssuer = new AccessTokenIssuer(azIdPConfig, jwkSet);
        this.authorize =
                new Authorize(clientStore, authorizationCodeStore, accessTokenIssuer, azIdPConfig);
        this.issueToken =
                new IssueToken(
                        azIdPConfig, authorizationCodeStore, accessTokenStore, accessTokenIssuer);
        this.clientRegistration = new DynamicClientRegistration(clientStore);
    }

    public AuthorizationResponse authorize(AuthorizationRequest authorizationRequest) {
        var parsed = authorizationRequestParser.parse(authorizationRequest);
        return authorize.authorize(parsed);
    }

    public TokenResponse issueToken(TokenRequest tokenRequest) {
        return issueToken.issue(tokenRequest);
    }

    public ClientRegistrationResponse registerClient(
            ClientRegistrationRequest clientRegistrationRequest) {
        return clientRegistration.register(clientRegistrationRequest);
    }
}
