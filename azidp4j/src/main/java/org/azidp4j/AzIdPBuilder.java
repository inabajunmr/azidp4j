package org.azidp4j;

import com.nimbusds.jose.jwk.JWKSet;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.StringJoiner;
import java.util.function.Supplier;
import org.azidp4j.authorize.authorizationcode.AuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeStore;
import org.azidp4j.authorize.authorizationcode.jwt.JwtAuthorizationCodeService;
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
import org.azidp4j.token.accesstoken.jwt.JwtAccessTokenService;
import org.azidp4j.token.refreshtoken.RefreshTokenService;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenService;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenStore;
import org.azidp4j.token.refreshtoken.jwt.JwtRefreshTokenService;

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
    private boolean isJwtAuthorizationCodeService = false;
    private Supplier<String> authorizationCodeServiceKidSupplier = null;
    private ScopeAudienceMapper scopeAudienceMapper = null;
    private AccessTokenService accessTokenService = null;
    private boolean isJwtAccessTokenService = false;
    private Supplier<String> accessTokenServiceKidSupplier = null;
    private RefreshTokenService refreshTokenService = null;
    private boolean isJwtRefreshTokenService = false;
    private Supplier<String> refreshTokenServiceKidSupplier = null;
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

    public AzIdPBuilder jwtAuthorizationCodeService(Supplier<String> kidSupplier) {
        this.authorizationCodeServiceKidSupplier = kidSupplier;
        this.isJwtAuthorizationCodeService = true;
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

    public AzIdPBuilder jwtAccessTokenService(Supplier<String> kidSupplier) {
        this.accessTokenServiceKidSupplier = kidSupplier;
        this.isJwtAccessTokenService = true;
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

    public AzIdPBuilder jwtRefreshTokenService(Supplier<String> kidSupplier) {
        this.refreshTokenServiceKidSupplier = kidSupplier;
        this.isJwtRefreshTokenService = true;
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

    public AzIdP build() {

        // validate
        List<String> errors = new ArrayList<>();
        validateIssuer(errors, issuer);
        required(errors, "scopesSupported", scopesSupported);
        required(errors, "defaultScopes", defaultScopes);
        required(errors, "accessTokenExpiration", accessTokenExpiration);
        required(errors, "authorizationCodeExpiration", authorizationCodeExpiration);
        required(errors, "refreshTokenExpiration", refreshTokenExpiration);
        required(errors, "grantTypesSupported", grantTypesSupported);
        required(errors, "discoveryConfig", discoveryConfig);
        required(errors, "clientStore", clientStore);
        required(errors, "scopeAudienceMapper", scopeAudienceMapper);
        if (grantTypesSupported != null && grantTypesSupported.contains(GrantType.password)) {
            required(errors, "userPasswordVerifier", userPasswordVerifier);
        }
        if (scopesSupported != null && scopesSupported.contains("openid")) {
            required(errors, "jwkSet", jwkSet);
            required(errors, "idTokenExpiration", idTokenExpiration);
        }

        constructJwtServices();

        // validate
        if (grantTypesSupported.contains(GrantType.authorization_code)) {
            required(errors, "authorizationCodeService", authorizationCodeService);
        }
        required(errors, "accessTokenService", accessTokenService);
        if (grantTypesSupported.contains(GrantType.refresh_token)) {
            required(errors, "refreshTokenService", refreshTokenService);
        }
        required(errors, "accessTokenService", accessTokenService);

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

    private void constructJwtServices() {
        // init jwt service
        if (isJwtAuthorizationCodeService) {
            this.authorizationCodeService =
                    new JwtAuthorizationCodeService(
                            jwkSet, issuer, authorizationCodeServiceKidSupplier);
        }
        if (isJwtAccessTokenService) {
            this.accessTokenService =
                    new JwtAccessTokenService(jwkSet, issuer, accessTokenServiceKidSupplier);
        }
        if (isJwtRefreshTokenService) {
            this.refreshTokenService =
                    new JwtRefreshTokenService(jwkSet, issuer, refreshTokenServiceKidSupplier);
        }
    }

    /**
     * ref. https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
     *
     * <p>REQUIRED. URL using the https scheme with no query or fragment component that the OP
     * asserts as its Issuer Identifier. If Issuer discovery is supported (see Section 2), this
     * value MUST be identical to the issuer value returned by WebFinger. This also MUST be
     * identical to the iss Claim value in ID Tokens issued from this Issuer.
     */
    private void validateIssuer(List<String> errors, String issuer) {
        // TODO test
        required(errors, "issuer", issuer);
        if (issuer == null) {
            return;
        }

        try {
            var uri = new URI(issuer);
            if (!uri.isAbsolute()) {
                errors.add("issuer isn't correct format.");
            }
            if (!uri.getScheme().equals("https") && !uri.getHost().equals("localhost")) {
                errors.add("issuer must be https.");
            }
            if (uri.getQuery() != null || uri.getFragment() != null) {
                errors.add("issuer must be url with no query or fragment.");
            }
        } catch (URISyntaxException e) {
            errors.add(e.getMessage());
        }
    }

    private List<String> required(List<String> errors, String name, Object value) {
        if (value == null) {
            errors.add(name + " is required.");
        }
        return errors;
    }
}
