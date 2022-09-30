package org.azidp4j;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.Map;
import org.azidp4j.authorize.*;
import org.azidp4j.client.*;
import org.azidp4j.discovery.Discovery;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.token.*;
import org.azidp4j.token.accesstoken.AccessTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.refreshtoken.RefreshTokenStore;

public class AzIdP {

    Discovery discovery;
    AuthorizationCodeStore authorizationCodeStore = new InMemoryAuthorizationCodeStore();
    Authorize authorize;
    AuthorizationRequestParser authorizationRequestParser = new AuthorizationRequestParser();
    IssueToken issueToken;
    TokenRequestParser tokenRequestParser = new TokenRequestParser();
    DynamicClientRegistration clientRegistration;
    ClientRegistrationRequestParser clientRegistrationRequestParser =
            new ClientRegistrationRequestParser();

    public AzIdP(
            AzIdPConfig azIdPConfig,
            JWKSet jwkSet,
            ClientStore clientStore,
            RefreshTokenStore refreshTokenStore,
            ScopeAudienceMapper scopeAudienceMapper) {
        this.discovery = new Discovery(azIdPConfig);
        var accessTokenIssuer = new AccessTokenIssuer(azIdPConfig, jwkSet, scopeAudienceMapper);
        var idTokenIssuer = new IDTokenIssuer(azIdPConfig, jwkSet);
        this.authorize =
                new Authorize(
                        clientStore,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        azIdPConfig);
        this.issueToken =
                new IssueToken(
                        azIdPConfig,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        refreshTokenStore,
                        null,
                        clientStore,
                        jwkSet);
        this.clientRegistration = new DynamicClientRegistration(clientStore);
    }

    public AzIdP(
            AzIdPConfig azIdPConfig,
            JWKSet jwkSet,
            ClientStore clientStore,
            RefreshTokenStore refreshTokenStore,
            ScopeAudienceMapper scopeAudienceMapper,
            UserPasswordVerifier userPasswordVerifier) {
        this.discovery = new Discovery(azIdPConfig);
        var accessTokenIssuer = new AccessTokenIssuer(azIdPConfig, jwkSet, scopeAudienceMapper);
        var idTokenIssuer = new IDTokenIssuer(azIdPConfig, jwkSet);
        this.authorize =
                new Authorize(
                        clientStore,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        azIdPConfig);
        this.issueToken =
                new IssueToken(
                        azIdPConfig,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        refreshTokenStore,
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

    public ClientRegistrationRequest parseClientRegistrationRequest(
            Map<String, Object> parameters) {
        return clientRegistrationRequestParser.parse(parameters);
    }

    public ClientRegistrationResponse registerClient(ClientRegistrationRequest request) {
        return clientRegistration.register(request);
    }

    public Map<String, Object> discovery() {
        return discovery.metadata();
    }
}
