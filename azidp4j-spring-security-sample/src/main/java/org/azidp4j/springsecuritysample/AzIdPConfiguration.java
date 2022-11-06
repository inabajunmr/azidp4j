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
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.request.ClientRequest;
import org.azidp4j.discovery.DiscoveryConfig;
import org.azidp4j.scope.ScopeAudienceMapper;
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
            RefreshTokenService refreshTokenService) {
        ScopeAudienceMapper scopeAudienceMapper = scope -> Set.of("rs.example.com");
        var discoveryConfig =
                DiscoveryConfig.builder()
                        .authorizationEndpoint(endpoint + "/authorize")
                        .tokenEndpoint(endpoint + "/token")
                        .jwksEndpoint(endpoint + "/.well-known/jwks.json")
                        .clientRegistrationEndpoint(endpoint + "/client")
                        .clientConfigurationEndpointPattern(endpoint + "/client/{CLIENT_ID}")
                        .userInfoEndpoint(endpoint + "/userinfo")
                        .build();
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
        var azIdp =
                AzIdP.init()
                        .issuer(endpoint)
                        .jwkSet(jwkSet)
                        .scopesSupported(Set.of("openid", "scope1", "scope2", "default"))
                        .defaultScopes(Set.of("openid", "scope1"))
                        .grantTypesSupported(
                                Set.of(
                                        GrantType.authorization_code,
                                        GrantType.implicit,
                                        GrantType.password,
                                        GrantType.client_credentials,
                                        GrantType.refresh_token))
                        .customClientStore(clientStore)
                        .customClientValidator(new ClientValidator())
                        .customAuthorizationCodeService(
                                authorizationCodeService) // TODO inMemory interface
                        .customScopeAudienceMapper(scopeAudienceMapper)
                        .customAccessTokenService(accessTokenService)
                        .customRefreshTokenService(refreshTokenService)
                        .userPasswordVerifier(userPasswordVerifier)
                        .discovery(discoveryConfig)
                        .build();
        var clientRegistration =
                new ClientRequest(
                        Map.of(
                                "redirect_uris",
                                        (Set.of(
                                                "http://client.example.com/callback1",
                                                "http://client.example.com/callback2")),
                                "grant_types",
                                        (Set.of(
                                                "authorization_code",
                                                "implicit",
                                                "refresh_token",
                                                "client_credentials")),
                                "scope", ("scope1 scope2 openid client"),
                                "response_types", (Set.of("code", "token", "id_token")),
                                "token_endpoint_auth_method", "client_secret_basic"));
        var client = azIdp.registerClient(clientRegistration);
        System.out.println(client.body);
        System.out.println(
                endpoint
                        + "/authorize?response_type=code&client_id="
                        + client.body.get("client_id")
                        + "&redirect_uri="
                        + URLEncoder.encode(
                                "http://client.example.com/callback1", StandardCharsets.UTF_8)
                        + "&scope=scope1");
        System.out.println(
                "curl -X POST -u "
                        + client.body.get("client_id")
                        + ":"
                        + client.body.get("client_secret")
                        + " -d 'grant_type=authorization_code' -d"
                        + " 'redirect_uri=http://client.example.com/callback1' -d 'code=xxx'"
                        + " "
                        + endpoint
                        + "token");
        return azIdp;
    }

    @Bean
    public JWKSet jwkSet() throws JOSEException {
        var es256 =
                new ECKeyGenerator(Curve.P_256)
                        .keyID("123")
                        .algorithm(new Algorithm("ES256"))
                        .generate();
        var rs256 =
                new RSAKeyGenerator(2048).keyID("abc").algorithm(new Algorithm("RS256")).generate();
        return new JWKSet(List.of(es256, rs256));
    }
}
