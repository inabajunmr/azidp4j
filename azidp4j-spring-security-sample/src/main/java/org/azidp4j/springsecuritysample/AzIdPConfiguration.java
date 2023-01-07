package org.azidp4j.springsecuritysample;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.azidp4j.AzIdP;
import org.azidp4j.authorize.authorizationcode.AuthorizationCodeService;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.TokenEndpointAuthMethod;
import org.azidp4j.client.request.ClientRequest;
import org.azidp4j.discovery.DiscoveryConfig;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.springsecuritysample.authentication.AcrValue;
import org.azidp4j.token.UserPasswordVerifier;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.refreshtoken.RefreshTokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AzIdPConfiguration {

    @Value("${endpoint}")
    private String endpoint;

    @Bean
    public AzIdP azIdP(
            ClientStore clientStore,
            JWKSet jwkSet,
            AuthorizationCodeService authorizationCodeService,
            AccessTokenService accessTokenService,
            RefreshTokenService refreshTokenService,
            IdTokenClaimsAssembler idTokenClaimsAssembler) {

        // The mapper is used for decision of JWT aud claims
        ScopeAudienceMapper scopeAudienceMapper = scope -> Set.of("rs.example.com");

        // Configure endpoints.
        var discoveryConfig =
                DiscoveryConfig.builder()
                        .authorizationEndpoint(endpoint + "/authorize")
                        .tokenEndpoint(endpoint + "/token")
                        .jwksEndpoint(endpoint + "/.well-known/jwks.json")
                        .clientRegistrationEndpoint(endpoint + "/client")
                        .userInfoEndpoint(endpoint + "/userinfo")
                        .build();

        // The verifier is used for Resource Owner Password Credential Grant.
        // If the service doesn't support the grant, it isn't required.
        var userPasswordVerifier =
                new UserPasswordVerifier() {
                    @Override
                    public boolean verify(String username, String password) {
                        return switch (username) {
                            case "user1" -> password.equals("password1");
                            case "user2" -> password.equals("password2");
                            case "user3" -> password.equals("password3");
                            default -> false;
                        };
                    }
                };

        // Initialize azidp4j.
        var azIdp =
                AzIdP.init()
                        .issuer(endpoint)
                        .jwkSet(jwkSet)
                        .idTokenKidSupplier(new IdTokenKidSupplier(jwkSet))
                        .idTokenClaimsAssembler(idTokenClaimsAssembler)
                        .scopesSupported(
                                Set.of(
                                        "openid", "profile", "email", "address", "phone", "scope1",
                                        "scope2", "client", "default"))
                        .defaultScopes(Set.of("openid", "scope1"))
                        .responseTypesSupported(
                                Set.of(
                                        Set.of(ResponseType.code),
                                        Set.of(ResponseType.token),
                                        Set.of(ResponseType.id_token),
                                        Set.of(ResponseType.code, ResponseType.token),
                                        Set.of(ResponseType.code, ResponseType.id_token),
                                        Set.of(ResponseType.token, ResponseType.id_token),
                                        Set.of(
                                                ResponseType.code,
                                                ResponseType.token,
                                                ResponseType.id_token)))
                        .grantTypesSupported(
                                Set.of(
                                        GrantType.authorization_code,
                                        GrantType.implicit,
                                        GrantType.password,
                                        GrantType.client_credentials,
                                        GrantType.refresh_token))
                        .tokenEndpointAuthMethodsSupported(
                                Set.of(
                                        TokenEndpointAuthMethod.client_secret_post,
                                        TokenEndpointAuthMethod.client_secret_basic,
                                        TokenEndpointAuthMethod.private_key_jwt,
                                        TokenEndpointAuthMethod.none))
                        .tokenEndpointAuthSigningAlgValuesSupported(Set.of("RS256", "ES256"))
                        .customClientStore(clientStore)
                        .customClientValidator(new JwtClientAuthNotAllowClientValidator())
                        .clientConfigurationEndpointIssuer(
                                (clientId) -> endpoint + "/client/" + clientId)
                        // integration test inject some type of service
                        // so don't use shortcut interface
                        .customAuthorizationCodeService(authorizationCodeService)
                        .customScopeAudienceMapper(scopeAudienceMapper)
                        .customAccessTokenService(accessTokenService)
                        .customRefreshTokenService(refreshTokenService)
                        .userPasswordVerifier(userPasswordVerifier)
                        .acrValuesSupported(
                                List.of(AcrValue.self_reported.value, AcrValue.pwd.value))
                        .discovery(discoveryConfig)
                        .build();

        // Register initial client.
        var clientRegistration =
                new ClientRequest(
                        Map.of(
                                "redirect_uris",
                                        (Set.of(
                                                "https://client.example.com/callback1",
                                                "https://client.example.com/callback2")),
                                "grant_types",
                                        (Set.of(
                                                "authorization_code",
                                                "implicit",
                                                "refresh_token",
                                                "client_credentials")),
                                "scope",
                                        ("scope1 scope2 openid profile email address phone client"),
                                "response_types", (Set.of("code", "token", "id_token")),
                                "token_endpoint_auth_method", "client_secret_basic"));
        var client = azIdp.registerClient(clientRegistration);

        // print client info / authorization request sample / token request sample.
        System.out.println(client.body);
        System.out.println(
                endpoint
                        + "/authorize?response_type=code&client_id="
                        + client.body.get("client_id")
                        + "&redirect_uri="
                        + URLEncoder.encode(
                                "https://client.example.com/callback1", StandardCharsets.UTF_8)
                        + "&scope=scope1&ui_locales=ja");
        System.out.println(
                "curl -X POST -u "
                        + client.body.get("client_id")
                        + ":"
                        + client.body.get("client_secret")
                        + " -d 'grant_type=authorization_code' -d"
                        + " 'redirect_uri=https://client.example.com/callback1' -d 'code=xxx'"
                        + " "
                        + endpoint
                        + "token");
        return azIdp;
    }

    @Bean
    public JWKSet jwkSet() throws JOSEException {
        // The implementation supports RS256/ES256
        var rs256 =
                new RSAKeyGenerator(2048).keyID("abc").algorithm(new Algorithm("RS256")).generate();
        var es256 =
                new ECKeyGenerator(Curve.P_256)
                        .keyID("123")
                        .algorithm(new Algorithm("ES256"))
                        .generate();
        return new JWKSet(List.of(rs256, es256));
    }
}
