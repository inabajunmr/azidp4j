package org.azidp4j;

import com.nimbusds.jose.jwk.JWKSet;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.StringJoiner;
import org.azidp4j.authorize.authorizationcode.AuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeStore;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.ClientValidator;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.discovery.DiscoveryConfig;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.token.UserPasswordVerifier;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.refreshtoken.RefreshTokenService;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenService;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenStore;

public class AzIdPBuilder {

    private String issuer = null;
    private JWKSet jwkSet = null;
    private Set<String> scopesSupported = null;
    private Set<String> defaultScopes = null;
    private Duration authorizationCodeExpiration = Duration.ofSeconds(60);
    private Duration accessTokenExpiration = Duration.ofMinutes(10);
    private Duration idTokenExpiration = Duration.ofMinutes(10);
    private Duration refreshTokenExpiration = Duration.ofDays(1);
    private Set<GrantType> grantTypesSupported =
            Set.of(GrantType.authorization_code, GrantType.implicit);
    private ClientStore clientStore = null;
    private ClientValidator clientValidator = null;
    private AuthorizationCodeService authorizationCodeService = null;
    private ScopeAudienceMapper scopeAudienceMapper = null;
    private AccessTokenService accessTokenService = null;
    private RefreshTokenService refreshTokenService = null;
    private DiscoveryConfig discoveryConfig = null;
    private UserPasswordVerifier userPasswordVerifier = null;

    public AzIdPBuilder issuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public AzIdPBuilder jwkSet(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
        return this;
    }

    public AzIdPBuilder scopesSupported(Set<String> scopes) {
        this.scopesSupported = scopes;
        return this;
    }

    public AzIdPBuilder defaultScopes(Set<String> scopes) {
        this.defaultScopes = scopes;
        return this;
    }

    public AzIdPBuilder authorizationCodeExpiration(Duration expiration) {
        this.authorizationCodeExpiration = expiration;
        return this;
    }

    public AzIdPBuilder accessTokenExpiration(Duration expiration) {
        this.accessTokenExpiration = expiration;
        return this;
    }

    public AzIdPBuilder idTokenExpiration(Duration expiration) {
        this.idTokenExpiration = expiration;
        return this;
    }

    public AzIdPBuilder refreshTokenExpiration(Duration expiration) {
        this.refreshTokenExpiration = expiration;
        return this;
    }

    public AzIdPBuilder grantTypesSupported(Set<GrantType> grantTypesSupported) {
        this.grantTypesSupported = grantTypesSupported;
        return this;
    }

    public AzIdPBuilder inMemoryClientStore() {
        this.clientStore = new InMemoryClientStore();
        return this;
    }

    public AzIdPBuilder customClientStore(ClientStore clientStore) {
        this.clientStore = clientStore;
        return this;
    }

    public AzIdPBuilder customClientValidator(ClientValidator clientValidator) {
        this.clientValidator = clientValidator;
        return this;
    }

    public AzIdPBuilder inMemoryAuthorizationCodeService() {
        this.authorizationCodeService =
                new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
        return this;
    }

    public AzIdPBuilder jwtAuthorizationCodeService() {
        // TODO other jwt services
        // TODO JwtAuthorizationCodeService needs to setup like JWKSet
        // how initialize this?
        return this;
    }

    public AzIdPBuilder customAuthorizationCodeService(
            AuthorizationCodeService authorizationCodeService) {
        this.authorizationCodeService = authorizationCodeService;
        return this;
    }

    public AzIdPBuilder staticScopeAudienceMapper(String audience) {
        this.scopeAudienceMapper = scope -> Set.of(audience);
        return this;
    }

    public AzIdPBuilder customScopeAudienceMapper(ScopeAudienceMapper mapper) {
        this.scopeAudienceMapper = mapper;
        return this;
    }

    public AzIdPBuilder inMemoryAccessTokenService() {
        this.accessTokenService = new InMemoryAccessTokenService(new InMemoryAccessTokenStore());
        return this;
    }

    public AzIdPBuilder customAccessTokenService(AccessTokenService accessTokenService) {
        this.accessTokenService = accessTokenService;
        return this;
    }

    public AzIdPBuilder inMemoryRefreshTokenService() {
        this.refreshTokenService = new InMemoryRefreshTokenService(new InMemoryRefreshTokenStore());
        return this;
    }

    public AzIdPBuilder customRefreshTokenService(RefreshTokenService refreshTokenService) {
        this.refreshTokenService = refreshTokenService;
        return this;
    }

    public AzIdPBuilder discovery(DiscoveryConfig discoveryConfig) {
        this.discoveryConfig = discoveryConfig;
        return this;
    }

    public AzIdPBuilder userPasswordVerifier(UserPasswordVerifier userPasswordVerifier) {
        this.userPasswordVerifier = userPasswordVerifier;
        return this;
    }

    public AzIdP buildOAuth2() {
        // validate
        List<String> errors = new ArrayList<>();
        required(errors, "issuer", issuer);
        required(errors, "scopesSupported", scopesSupported);
        required(errors, "defaultScopes", defaultScopes);
        required(errors, "accessTokenExpiration", accessTokenExpiration);
        required(errors, "authorizationCodeExpiration", authorizationCodeExpiration);
        required(errors, "refreshTokenExpiration", refreshTokenExpiration);
        required(errors, "discoveryConfig", discoveryConfig);
        required(errors, "clientStore", clientStore);
        if (grantTypesSupported.contains(GrantType.authorization_code)) {
            required(errors, "authorizationCodeService", authorizationCodeService);
        }
        required(errors, "accessTokenService", accessTokenService);
        if (grantTypesSupported.contains(GrantType.refresh_token)) {
            required(errors, "refreshTokenService", refreshTokenService);
        }
        required(errors, "scopeAudienceMapper", scopeAudienceMapper);
        if (grantTypesSupported.contains(GrantType.password)) {
            required(errors, "userPasswordVerifier", userPasswordVerifier);
        }

        if (!errors.isEmpty()) {
            var joiner = new StringJoiner("\n");
            errors.forEach(msg -> joiner.add(msg));
            throw new AssertionError(joiner.toString());
        }

        var config =
                new AzIdPConfig(
                        issuer,
                        scopesSupported,
                        defaultScopes,
                        grantTypesSupported,
                        accessTokenExpiration,
                        authorizationCodeExpiration,
                        refreshTokenExpiration,
                        idTokenExpiration);
        return new AzIdP(
                config,
                discoveryConfig,
                jwkSet,
                clientStore,
                clientValidator,
                authorizationCodeService,
                accessTokenService,
                refreshTokenService,
                scopeAudienceMapper,
                userPasswordVerifier);
    }

    public List<String> required(List<String> errors, String name, Object value) {
        if (value == null) {
            errors.add(name + " is required.");
        }
        return errors;
    }

    public AzIdP buildOIDC() {
        // TODO validate
        var config =
                new AzIdPConfig(
                        issuer,
                        scopesSupported,
                        defaultScopes,
                        grantTypesSupported,
                        accessTokenExpiration,
                        authorizationCodeExpiration,
                        refreshTokenExpiration,
                        idTokenExpiration);
        return new AzIdP(
                config,
                discoveryConfig,
                jwkSet,
                clientStore,
                clientValidator,
                authorizationCodeService,
                accessTokenService,
                refreshTokenService,
                scopeAudienceMapper,
                userPasswordVerifier);
    }
}
