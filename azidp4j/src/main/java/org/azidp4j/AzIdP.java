package org.azidp4j;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.Map;
import org.azidp4j.authorize.*;
import org.azidp4j.authorize.request.AuthorizationRequest;
import org.azidp4j.authorize.request.AuthorizationRequestParser;
import org.azidp4j.client.*;
import org.azidp4j.discovery.Discovery;
import org.azidp4j.introspection.Introspect;
import org.azidp4j.introspection.IntrospectionRequest;
import org.azidp4j.introspection.IntrospectionRequestParser;
import org.azidp4j.introspection.IntrospectionResponse;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.token.*;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.accesstoken.AccessTokenStore;
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
    Introspect introspect;
    IntrospectionRequestParser introspectionRequestParser = new IntrospectionRequestParser();
    ClientRegistrationRequestParser clientRegistrationRequestParser =
            new ClientRegistrationRequestParser();
    ClientConfigurationRequestParser clientConfigurationRequestParser =
            new ClientConfigurationRequestParser();

    public AzIdP(
            AzIdPConfig azIdPConfig,
            JWKSet jwkSet,
            ClientStore clientStore,
            AccessTokenService accessTokenService,
            AccessTokenStore accessTokenStore,
            RefreshTokenStore refreshTokenStore,
            ScopeAudienceMapper scopeAudienceMapper) {
        this.discovery = new Discovery(azIdPConfig);
        var idTokenIssuer = new IDTokenIssuer(azIdPConfig, jwkSet);
        this.authorize =
                new Authorize(
                        clientStore,
                        authorizationCodeStore,
                        accessTokenService,
                        idTokenIssuer,
                        azIdPConfig);
        this.issueToken =
                new IssueToken(
                        azIdPConfig,
                        authorizationCodeStore,
                        accessTokenStore,
                        idTokenIssuer,
                        refreshTokenStore,
                        scopeAudienceMapper,
                        null,
                        clientStore,
                        jwkSet);
        this.clientRegistration =
                new DynamicClientRegistration(azIdPConfig, clientStore, accessTokenStore, jwkSet);
        this.introspect = new Introspect(accessTokenStore, refreshTokenStore, azIdPConfig);
    }

    public AzIdP(
            AzIdPConfig azIdPConfig,
            JWKSet jwkSet,
            ClientStore clientStore,
            AccessTokenService accessTokenService,
            AccessTokenStore accessTokenStore,
            RefreshTokenStore refreshTokenStore,
            ScopeAudienceMapper scopeAudienceMapper,
            UserPasswordVerifier userPasswordVerifier) {
        this.discovery = new Discovery(azIdPConfig);
        var idTokenIssuer = new IDTokenIssuer(azIdPConfig, jwkSet);
        this.authorize =
                new Authorize(
                        clientStore,
                        authorizationCodeStore,
                        accessTokenService,
                        idTokenIssuer,
                        azIdPConfig);
        this.issueToken =
                new IssueToken(
                        azIdPConfig,
                        authorizationCodeStore,
                        accessTokenStore,
                        idTokenIssuer,
                        refreshTokenStore,
                        scopeAudienceMapper,
                        userPasswordVerifier,
                        clientStore,
                        jwkSet);
        this.clientRegistration =
                new DynamicClientRegistration(azIdPConfig, clientStore, accessTokenStore, jwkSet);
        this.introspect = new Introspect(accessTokenStore, refreshTokenStore, azIdPConfig);
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

    public ClientConfigurationRequest parseClientConfigurationRequest(
            String clientId, Map<String, Object> parameters) {
        return clientConfigurationRequestParser.parse(clientId, parameters);
    }

    public ClientRegistrationResponse configureRequest(ClientConfigurationRequest request) {
        return clientRegistration.configure(request);
    }

    public ClientDeleteResponse delete(String clientId) {
        return clientRegistration.delete(clientId);
    }

    public IntrospectionResponse introspect(IntrospectionRequest request) {
        return introspect.introspect(introspectionRequestParser.parse(request));
    }

    public Map<String, Object> discovery() {
        return discovery.metadata();
    }
}
