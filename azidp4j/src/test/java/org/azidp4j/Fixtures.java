package org.azidp4j;

import com.nimbusds.jose.jwk.JWKSet;
import java.text.ParseException;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.azidp4j.authorize.request.CodeChallengeMethod;
import org.azidp4j.authorize.request.ResponseMode;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.*;
import org.azidp4j.discovery.DiscoveryConfig;
import org.azidp4j.scope.SampleScopeAudienceMapper;

public class Fixtures {

    public static AzIdPBuilder azIdPBuilder(JWKSet jwkSet) {
        return AzIdP.initInMemory()
                .jwkSet(jwkSet)
                .idTokenKidSupplier((alg) -> jwkSet.getKeys().get(0).getKeyID())
                .issuer("http://localhost:8080")
                .grantTypesSupported(
                        Set.of(
                                GrantType.authorization_code,
                                GrantType.implicit,
                                GrantType.refresh_token,
                                GrantType.password,
                                GrantType.client_credentials))
                .scopesSupported(Set.of("openid", "rs:scope1", "rs:scope2", "rs:scope3", "default"))
                .defaultScopes(Set.of("openid", "rs:scope1"))
                .discovery(Fixtures.discoveryConfig())
                .customScopeAudienceMapper(new SampleScopeAudienceMapper())
                .userPasswordVerifier((username, password) -> true);
    }

    public static AzIdPConfig azIdPConfig() {
        return new AzIdPConfig(
                "http://localhost:8080",
                Set.of("openid", "rs:scope1", "rs:scope2", "rs:scope3", "default"),
                Set.of("openid", "rs:scope1"),
                Set.of(
                        TokenEndpointAuthMethod.client_secret_basic,
                        TokenEndpointAuthMethod.private_key_jwt),
                Set.of(SigningAlgorithm.RS256),
                Set.of(
                        TokenEndpointAuthMethod.client_secret_basic,
                        TokenEndpointAuthMethod.private_key_jwt),
                Set.of(SigningAlgorithm.ES256),
                Set.of(
                        TokenEndpointAuthMethod.client_secret_basic,
                        TokenEndpointAuthMethod.private_key_jwt),
                Set.of(SigningAlgorithm.RS256),
                Set.of(
                        GrantType.authorization_code,
                        GrantType.implicit,
                        GrantType.password,
                        GrantType.client_credentials,
                        GrantType.refresh_token),
                Set.of(
                        Set.of(ResponseType.code),
                        Set.of(ResponseType.token),
                        Set.of(ResponseType.id_token),
                        Set.of(ResponseType.code, ResponseType.token),
                        Set.of(ResponseType.code, ResponseType.id_token),
                        Set.of(ResponseType.token, ResponseType.id_token),
                        Set.of(ResponseType.code, ResponseType.token, ResponseType.id_token)),
                Set.of(ResponseMode.query, ResponseMode.fragment),
                Set.of(SigningAlgorithm.ES256, SigningAlgorithm.RS256, SigningAlgorithm.none),
                List.of("acr1", "acr2"),
                Duration.ofSeconds(3600),
                Duration.ofSeconds(600),
                Duration.ofSeconds(604800),
                Duration.ofSeconds(3600),
                Set.of(CodeChallengeMethod.S256));
    }

    public static DiscoveryConfig discoveryConfig() {
        return DiscoveryConfig.builder()
                .authorizationEndpoint("http://localhost:8080/authorize")
                .tokenEndpoint("http://localhost:8080/token")
                .jwksEndpoint("http://localhost:8080/.well-known/jwks.json")
                .clientRegistrationEndpoint("http://localhost:8080/client")
                .userInfoEndpoint("http://localhost:8080/userinfo")
                .build();
    }

    public static ClientBuilder clientBuilder() {
        var builder = new ClientBuilder();
        builder.clientId(UUID.randomUUID().toString());
        builder.redirectUris(Set.of("https://rp1.example.com", "https://rp2.example.com"));
        builder.responseTypes(
                Set.of(
                        Set.of(ResponseType.code),
                        Set.of(ResponseType.token),
                        Set.of(ResponseType.id_token),
                        Set.of(ResponseType.none),
                        Set.of(ResponseType.code, ResponseType.token),
                        Set.of(ResponseType.code, ResponseType.id_token),
                        Set.of(ResponseType.id_token, ResponseType.token),
                        Set.of(ResponseType.code, ResponseType.token, ResponseType.id_token)));
        builder.applicationType(ApplicationType.WEB);
        builder.scope("rs:scope1 rs:scope2 openid");
        return builder;
    }

    public static ClientBuilder publicClient() {
        var builder = clientBuilder();
        builder.tokenEndpointAuthMethod(TokenEndpointAuthMethod.none);
        builder.requireAuthTime(false);
        builder.grantTypes(
                Set.of(
                        GrantType.authorization_code,
                        GrantType.implicit,
                        GrantType.refresh_token,
                        GrantType.password));
        return builder;
    }

    public static ClientBuilder confidentialClient() {
        var builder = clientBuilder();
        builder.clientSecret("secret");
        builder.tokenEndpointAuthMethod(TokenEndpointAuthMethod.client_secret_basic);
        builder.idTokenSignedResponseAlg(SigningAlgorithm.ES256);
        builder.grantTypes(
                Set.of(
                        GrantType.authorization_code,
                        GrantType.implicit,
                        GrantType.password,
                        GrantType.refresh_token,
                        GrantType.client_credentials));
        return builder;
    }

    public static ClientBuilder noGrantTypeClient() {
        var builder = confidentialClient();
        builder.grantTypes(Set.of());
        return builder;
    }

    public static ClientBuilder authorizationCodeClient() {
        var builder = clientBuilder();
        builder.responseTypes(Set.of(Set.of(ResponseType.code)));
        builder.clientSecret("secret");
        builder.grantTypes(Set.of(GrantType.authorization_code));
        builder.tokenEndpointAuthMethod(TokenEndpointAuthMethod.client_secret_basic);
        builder.idTokenSignedResponseAlg(SigningAlgorithm.ES256);
        return builder;
    }

    public static ClientBuilder noResponseTypeClient() {
        var builder = clientBuilder();
        builder.clientSecret("secret");
        builder.responseTypes(Set.of());
        builder.tokenEndpointAuthMethod(TokenEndpointAuthMethod.client_secret_basic);
        builder.idTokenSignedResponseAlg(SigningAlgorithm.ES256);
        builder.grantTypes(
                Set.of(
                        GrantType.authorization_code,
                        GrantType.implicit,
                        GrantType.password,
                        GrantType.refresh_token,
                        GrantType.client_credentials));
        return builder;
    }

    public static JWKSet jwkSet() {
        // from conformance test
        var jwkSet =
                """
                {"keys":[{"kty":"RSA","e":"AQAB","use":"sig","alg":"RS256","n":"hNdk44dzDC8_SimAX4YgnQSTBOl4hhVP_p4sT4Nf3IhiG5L3CUYaOm6WkAKwPHWFaD8Zt4_WIk-PESY-SEBWcRzn-Ae7vXyHubxbC6eMc5dA5dC7yLVfmzYGbJpzWT_9TxWQKB8Kpk0leIPiul3sLMBCQ1F-jOeHsW2xKuskrnjqwDxCGxMBKXiKJnAVQboJzP9iDDxZgur29Dbapt7xApUu-TmYNlFzMG8PdaDN6ZqeN-PZdP10NX0xmRf7sGSSoHr7y5wQ7dfFvbus9YTuaOyg9ku5VSV-w51qPkCRBFchZkxoA6a8h1rprmHWjEt_3U-RwljEhryL-avO8wTKaQ"}]}
                """;
        try {
            return JWKSet.parse(jwkSet);
        } catch (ParseException e) {
            throw new AssertionError(e);
        }
    }
}
