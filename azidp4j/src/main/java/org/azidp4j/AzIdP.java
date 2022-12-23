package org.azidp4j;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;
import org.azidp4j.authorize.*;
import org.azidp4j.authorize.authorizationcode.AuthorizationCodeService;
import org.azidp4j.authorize.request.AuthorizationRequest;
import org.azidp4j.authorize.request.AuthorizationRequestParser;
import org.azidp4j.authorize.response.AuthorizationResponse;
import org.azidp4j.client.*;
import org.azidp4j.client.request.ClientRequest;
import org.azidp4j.client.response.ClientDeleteResponse;
import org.azidp4j.client.response.ClientReadResponse;
import org.azidp4j.client.response.ClientRegistrationResponse;
import org.azidp4j.discovery.Discovery;
import org.azidp4j.discovery.DiscoveryConfig;
import org.azidp4j.introspection.Introspect;
import org.azidp4j.introspection.request.IntrospectionRequest;
import org.azidp4j.introspection.response.IntrospectionResponse;
import org.azidp4j.revocation.Revocation;
import org.azidp4j.revocation.request.RevocationRequest;
import org.azidp4j.revocation.response.RevocationResponse;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.token.*;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.idtoken.IDTokenClaimsAssembler;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenValidator;
import org.azidp4j.token.refreshtoken.RefreshTokenService;
import org.azidp4j.token.request.TokenRequest;
import org.azidp4j.token.response.TokenResponse;

public class AzIdP {

    private final Discovery discovery;
    private final Authorize authorize;
    private final AuthorizationRequestParser authorizationRequestParser =
            new AuthorizationRequestParser();
    private final IssueToken issueToken;
    private final DynamicClientRegistration clientRegistration;
    private final Introspect introspect;
    private final Revocation revocation;

    public static AzIdPBuilder init() {
        return new AzIdPBuilder();
    }

    public static AzIdPBuilder initInMemory() {
        return new AzIdPBuilder()
                .inMemoryClientStore()
                .inMemoryAuthorizationCodeService()
                .inMemoryAccessTokenService()
                .inMemoryRefreshTokenService()
                .inMemoryAuthorizationCodeService();
    }

    public static AzIdPBuilder initJwt(
            Supplier<String> authorizationCodeKidSupplier,
            Supplier<String> accessTokenKidSupplier,
            Supplier<String> refreshTokenKidSupplier) {
        return new AzIdPBuilder()
                .jwtAuthorizationCodeService(authorizationCodeKidSupplier)
                .jwtAccessTokenService(accessTokenKidSupplier)
                .jwtRefreshTokenService(refreshTokenKidSupplier);
    }

    protected AzIdP(
            AzIdPConfig azIdPConfig,
            DiscoveryConfig discoveryConfig,
            JWKSet jwkSet,
            Function<SigningAlgorithm, String> kidSupplier,
            IDTokenClaimsAssembler idTokenClaimsAssembler,
            ClientStore clientStore,
            ClientValidator clientValidator,
            Function<String, String> clientConfigurationEndpointIssuer,
            AuthorizationCodeService authorizationCodeService,
            AccessTokenService accessTokenService,
            RefreshTokenService refreshTokenService,
            ScopeAudienceMapper scopeAudienceMapper,
            UserPasswordVerifier userPasswordVerifier) {
        this.discovery = new Discovery(azIdPConfig, discoveryConfig);
        var idTokenIssuer =
                new IDTokenIssuer(azIdPConfig, jwkSet, kidSupplier, idTokenClaimsAssembler);
        this.authorize =
                new Authorize(
                        clientStore,
                        authorizationCodeService,
                        scopeAudienceMapper,
                        accessTokenService,
                        idTokenIssuer,
                        new IDTokenValidator(azIdPConfig, jwkSet),
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
                        azIdPConfig,
                        clientStore,
                        clientValidator,
                        accessTokenService,
                        clientConfigurationEndpointIssuer);
        this.introspect = new Introspect(accessTokenService, refreshTokenService, azIdPConfig);
        this.revocation = new Revocation(accessTokenService, refreshTokenService, clientStore);
    }

    /**
     * Process authorization request
     *
     * @param authorizationRequest authorizationRequest
     * @return what should do next
     */
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

    public ClientDeleteResponse deleteClient(String clientId) {
        return clientRegistration.delete(clientId);
    }

    public ClientReadResponse readClient(String clientId) {
        return clientRegistration.read(clientId);
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
