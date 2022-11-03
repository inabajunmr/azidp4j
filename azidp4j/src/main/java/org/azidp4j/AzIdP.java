package org.azidp4j;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.Map;
import org.azidp4j.authorize.*;
import org.azidp4j.authorize.authorizationcode.AuthorizationCodeService;
import org.azidp4j.authorize.request.AuthorizationRequest;
import org.azidp4j.authorize.request.AuthorizationRequestParser;
import org.azidp4j.authorize.response.AuthorizationResponse;
import org.azidp4j.client.*;
import org.azidp4j.client.request.ClientRequest;
import org.azidp4j.client.request.ClientRequestParser;
import org.azidp4j.client.response.ClientDeleteResponse;
import org.azidp4j.client.response.ClientRegistrationResponse;
import org.azidp4j.discovery.Discovery;
import org.azidp4j.introspection.Introspect;
import org.azidp4j.introspection.request.IntrospectionRequest;
import org.azidp4j.introspection.response.IntrospectionResponse;
import org.azidp4j.revocation.Revocation;
import org.azidp4j.revocation.request.RevocationRequest;
import org.azidp4j.revocation.response.RevocationResponse;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.token.*;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.refreshtoken.RefreshTokenService;
import org.azidp4j.token.request.TokenRequest;
import org.azidp4j.token.request.TokenRequestParser;
import org.azidp4j.token.response.TokenResponse;

public class AzIdP {

    private final Discovery discovery;
    private final Authorize authorize;
    private final AuthorizationRequestParser authorizationRequestParser =
            new AuthorizationRequestParser();
    private final IssueToken issueToken;
    private final TokenRequestParser tokenRequestParser = new TokenRequestParser();
    private final DynamicClientRegistration clientRegistration;
    private final Introspect introspect;
    private final Revocation revocation;
    private final ClientRequestParser clientRequestParser = new ClientRequestParser();

    public AzIdP(
            AzIdPConfig azIdPConfig,
            JWKSet jwkSet,
            ClientStore clientStore,
            ClientValidator clientValidator,
            AuthorizationCodeService authorizationCodeService,
            AccessTokenService accessTokenService,
            RefreshTokenService refreshTokenService,
            ScopeAudienceMapper scopeAudienceMapper) {
        this.discovery = new Discovery(azIdPConfig);
        var idTokenIssuer = new IDTokenIssuer(azIdPConfig, jwkSet);
        this.authorize =
                new Authorize(
                        clientStore,
                        authorizationCodeService,
                        scopeAudienceMapper,
                        accessTokenService,
                        idTokenIssuer,
                        azIdPConfig);
        this.issueToken =
                new IssueToken(
                        azIdPConfig,
                        authorizationCodeService,
                        accessTokenService,
                        idTokenIssuer,
                        refreshTokenService,
                        scopeAudienceMapper,
                        null,
                        clientStore);
        this.clientRegistration =
                new DynamicClientRegistration(
                        azIdPConfig, clientStore, clientValidator, accessTokenService);
        this.introspect = new Introspect(accessTokenService, refreshTokenService, azIdPConfig);
        this.revocation = new Revocation(accessTokenService, refreshTokenService, clientStore);
    }

    public AzIdP(
            AzIdPConfig azIdPConfig,
            JWKSet jwkSet,
            ClientStore clientStore,
            ClientValidator clientValidator,
            AuthorizationCodeService authorizationCodeService,
            AccessTokenService accessTokenService,
            RefreshTokenService refreshTokenService,
            ScopeAudienceMapper scopeAudienceMapper,
            UserPasswordVerifier userPasswordVerifier) {
        this.discovery = new Discovery(azIdPConfig);
        var idTokenIssuer = new IDTokenIssuer(azIdPConfig, jwkSet);
        this.authorize =
                new Authorize(
                        clientStore,
                        authorizationCodeService,
                        scopeAudienceMapper,
                        accessTokenService,
                        idTokenIssuer,
                        azIdPConfig);
        this.issueToken =
                new IssueToken(
                        azIdPConfig,
                        authorizationCodeService,
                        accessTokenService,
                        idTokenIssuer,
                        refreshTokenService,
                        scopeAudienceMapper,
                        userPasswordVerifier,
                        clientStore);
        this.clientRegistration =
                new DynamicClientRegistration(
                        azIdPConfig, clientStore, clientValidator, accessTokenService);
        this.introspect = new Introspect(accessTokenService, refreshTokenService, azIdPConfig);
        this.revocation = new Revocation(accessTokenService, refreshTokenService, clientStore);
    }

    public AuthorizationResponse authorize(AuthorizationRequest authorizationRequest) {
        var parsed = authorizationRequestParser.parse(authorizationRequest);
        return authorize.authorize(parsed);
    }

    public TokenResponse issueToken(TokenRequest tokenRequest) {
        return issueToken.issue(tokenRequest);
    }

    public ClientRegistrationResponse registerClient(ClientRequest request) {
        return clientRegistration.register(request);
    }

    public ClientDeleteResponse delete(String clientId) {
        return clientRegistration.delete(clientId);
    }

    public IntrospectionResponse introspect(IntrospectionRequest request) {
        return introspect.introspect(request);
    }

    public RevocationResponse revoke(RevocationRequest request) {
        return revocation.revoke(request);
    }

    public Map<String, Object> discovery() {
        return discovery.metadata();
    }
}
