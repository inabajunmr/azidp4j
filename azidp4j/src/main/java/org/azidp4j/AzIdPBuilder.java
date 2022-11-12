package org.azidp4j;

import com.nimbusds.jose.jwk.JWKSet;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.StringJoiner;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.azidp4j.authorize.authorizationcode.AuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeStore;
import org.azidp4j.authorize.authorizationcode.jwt.JwtAuthorizationCodeService;
import org.azidp4j.authorize.request.ResponseMode;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.*;
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
    private JWKSet jwkSet;
    private Set<SigningAlgorithm> idTokenSigningAlgValuesSupported;
    private Function<SigningAlgorithm, String> idTokenKidSupplier;
    private Set<String> scopesSupported = null;
    private Set<String> defaultScopes = null;
    private Duration authorizationCodeExpiration = Duration.ofSeconds(60);
    private Duration accessTokenExpiration = Duration.ofMinutes(10);
    private Duration idTokenExpiration = Duration.ofMinutes(10);
    private Duration refreshTokenExpiration = Duration.ofDays(1);
    private Set<GrantType> grantTypesSupported =
            Set.of(GrantType.authorization_code, GrantType.implicit);
    private Set<Set<ResponseType>> responseTypesSupported;
    private Set<ResponseMode> responseModesSupported =
            Set.of(ResponseMode.query, ResponseMode.fragment);
    private ClientStore clientStore = null;
    private ClientValidator clientValidator = null;
    private Function<String, String> clientConfigurationEndpointIssuer;
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

    public AzIdPBuilder idTokenSigningAlgValuesSupported(
            Set<SigningAlgorithm> idTokenSigningAlgValuesSupported) {
        this.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
        return this;
    }

    public AzIdPBuilder idTokenKidSupplier(Function<SigningAlgorithm, String> idTokenKidSupplier) {
        this.idTokenKidSupplier = idTokenKidSupplier;
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

    public AzIdPBuilder responseTypesSupported(Set<Set<ResponseType>> responseTypesSupported) {
        this.responseTypesSupported = responseTypesSupported;
        return this;
    }

    public AzIdPBuilder responseModesSupported(Set<ResponseMode> responseModesSupported) {
        this.responseModesSupported = responseModesSupported;
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

    public AzIdPBuilder clientConfigurationEndpointIssuer(
            Function<String, String> clientConfigurationEndpointIssuer) {
        this.clientConfigurationEndpointIssuer = clientConfigurationEndpointIssuer;
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
        if (defaultScopes == null) {
            defaultScopes = Set.of();
        }
        required(errors, "accessTokenExpiration", accessTokenExpiration);
        required(errors, "authorizationCodeExpiration", authorizationCodeExpiration);
        required(errors, "refreshTokenExpiration", refreshTokenExpiration);
        required(errors, "grantTypesSupported", grantTypesSupported);
        required(errors, "responseModesSupported", responseModesSupported);
        required(errors, "discoveryConfig", discoveryConfig);
        required(errors, "clientStore", clientStore);
        required(errors, "scopeAudienceMapper", scopeAudienceMapper);
        if (grantTypesSupported != null && grantTypesSupported.contains(GrantType.password)) {
            required(errors, "userPasswordVerifier", userPasswordVerifier);
        }
        if (grantTypesSupported != null
                && (grantTypesSupported.contains(GrantType.authorization_code)
                        || grantTypesSupported.contains(GrantType.implicit))) {
            if (responseModesSupported != null && responseModesSupported.size() == 0) {
                errors.add("responseModesSupported is required");
            }
        }

        defaultResponseTypesSupported();

        if (isOpenId()) {
            required(errors, "jwkSet", jwkSet);
            required(errors, "idTokenKidSupplier", idTokenKidSupplier);
            required(errors, "idTokenExpiration", idTokenExpiration);
            if (idTokenSigningAlgValuesSupported == null) {
                idTokenSigningAlgValuesSupported =
                        jwkSet.getKeys().stream()
                                .map(v -> SigningAlgorithm.of(v.getAlgorithm().getName()))
                                .collect(Collectors.toSet());
            }
        }
        validateIdTokenSigningAlgAndJwkSet(errors);
        constructJwtServices();
        validateTokenServices(errors);

        if (!errors.isEmpty()) {
            var joiner = new StringJoiner("\n");
            errors.forEach(joiner::add);
            throw new IllegalArgumentException(joiner.toString());
        }

        var config =
                new AzIdPConfig(
                        issuer,
                        scopesSupported,
                        defaultScopes,
                        grantTypesSupported,
                        responseTypesSupported,
                        responseModesSupported,
                        idTokenSigningAlgValuesSupported,
                        accessTokenExpiration,
                        authorizationCodeExpiration,
                        refreshTokenExpiration,
                        idTokenExpiration);
        return new AzIdP(
                config,
                discoveryConfig,
                jwkSet,
                idTokenKidSupplier,
                clientStore,
                clientValidator,
                clientConfigurationEndpointIssuer,
                authorizationCodeService,
                accessTokenService,
                refreshTokenService,
                scopeAudienceMapper,
                userPasswordVerifier);
    }

    private void validateTokenServices(List<String> errors) {
        if (grantTypesSupported.contains(GrantType.authorization_code)) {
            required(errors, "authorizationCodeService", authorizationCodeService);
        }
        required(errors, "accessTokenService", accessTokenService);
        if (grantTypesSupported.contains(GrantType.refresh_token)) {
            required(errors, "refreshTokenService", refreshTokenService);
        }
        required(errors, "accessTokenService", accessTokenService);
    }

    private void validateIdTokenSigningAlgAndJwkSet(List<String> errors) {
        if (!isOpenId()) {
            return;
        }
        idTokenSigningAlgValuesSupported.forEach(
                alg -> {
                    if (alg == SigningAlgorithm.none) {
                        return;
                    }
                    var kid = idTokenKidSupplier.apply(alg);
                    if (jwkSet.getKeyByKeyId(kid) == null) {
                        errors.add(
                                "idTokenKidSupplier supply "
                                        + kid
                                        + " but jwkSet doesn't have "
                                        + kid);
                    }
                });
    }

    private boolean isOpenId() {
        if (scopesSupported == null) {
            return false;
        }
        return scopesSupported.contains("openid");
    }

    private void defaultResponseTypesSupported() {
        if (responseTypesSupported != null) {
            return;
        }

        if (!grantTypesSupported.contains(GrantType.implicit)) {
            responseTypesSupported = Set.of(Set.of(ResponseType.code));
            return;
        }

        if (scopesSupported != null && scopesSupported.contains("openid")) {
            responseTypesSupported =
                    Set.of(
                            Set.of(ResponseType.code),
                            Set.of(ResponseType.token),
                            Set.of(ResponseType.id_token),
                            Set.of(ResponseType.token, ResponseType.id_token));
        } else {
            responseTypesSupported = Set.of(Set.of(ResponseType.code), Set.of(ResponseType.token));
        }
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
        required(errors, "issuer", issuer);
        if (issuer == null) {
            return;
        }

        try {
            var uri = new URI(issuer);
            if (!uri.isAbsolute()) {
                errors.add("issuer isn't correct format.");
                return;
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

    private void required(List<String> errors, String name, Object value) {
        if (value == null) {
            errors.add(name + " is required.");
        }
    }
}
