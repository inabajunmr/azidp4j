package org.azidp4j;

import com.nimbusds.jose.jwk.JWKSet;
import org.azidp4j.authorize.*;
import org.azidp4j.client.ClientRegistrationRequest;
import org.azidp4j.client.ClientRegistrationResponse;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.DynamicClientRegistration;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.token.*;
import org.azidp4j.token.accesstoken.AccessTokenIssuer;
import org.azidp4j.token.refreshtoken.RefreshTokenIssuer;

public class AzIdP {

    AuthorizationCodeStore authorizationCodeStore = new InMemoryAuthorizationCodeStore();
    Authorize authorize;
    AuthorizationRequestParser authorizationRequestParser = new AuthorizationRequestParser();
    IssueToken issueToken;
    TokenRequestParser tokenRequestParser = new TokenRequestParser();
    DynamicClientRegistration clientRegistration;

    public AzIdP(
            AzIdPConfig azIdPConfig,
            JWKSet jwkSet,
            ClientStore clientStore,
            ScopeAudienceMapper scopeAudienceMapper) {
        var accessTokenIssuer = new AccessTokenIssuer(azIdPConfig, jwkSet, scopeAudienceMapper);
        var refreshTokenIssuer = new RefreshTokenIssuer(azIdPConfig, jwkSet, scopeAudienceMapper);
        this.authorize =
                new Authorize(clientStore, authorizationCodeStore, accessTokenIssuer, azIdPConfig);
        this.issueToken =
                new IssueToken(
                        azIdPConfig,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        refreshTokenIssuer,
                        null,
                        clientStore,
                        jwkSet);
        this.clientRegistration = new DynamicClientRegistration(clientStore);
    }

    public AzIdP(
            AzIdPConfig azIdPConfig,
            JWKSet jwkSet,
            ClientStore clientStore,
            ScopeAudienceMapper scopeAudienceMapper,
            UserPasswordVerifier userPasswordVerifier) {
        var accessTokenIssuer = new AccessTokenIssuer(azIdPConfig, jwkSet, scopeAudienceMapper);
        var refreshTokenIssuer = new RefreshTokenIssuer(azIdPConfig, jwkSet, scopeAudienceMapper);
        this.authorize =
                new Authorize(clientStore, authorizationCodeStore, accessTokenIssuer, azIdPConfig);
        this.issueToken =
                new IssueToken(
                        azIdPConfig,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        refreshTokenIssuer,
                        userPasswordVerifier,
                        clientStore,
                        jwkSet);
        this.clientRegistration = new DynamicClientRegistration(clientStore);
    }

    public AuthorizationResponse authorize(AuthorizationRequest authorizationRequest) {
        var parsed = authorizationRequestParser.parse(authorizationRequest);
        return authorize.authorize(parsed);
    }

    public TokenResponse issueToken(TokenRequest tokenRequest) {
        var parsed = tokenRequestParser.parse(tokenRequest);
        return issueToken.issue(parsed);
    }

    public ClientRegistrationResponse registerClient(
            ClientRegistrationRequest clientRegistrationRequest) {
        return clientRegistration.register(clientRegistrationRequest);
    }
}
