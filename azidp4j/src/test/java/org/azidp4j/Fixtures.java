package org.azidp4j;

import com.nimbusds.jose.jwk.JWKSet;
import java.text.ParseException;
import java.time.Duration;
import java.util.List;
import java.util.Set;
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
                Set.of(TokenEndpointAuthMethod.client_secret_basic),
                null,
                Set.of(TokenEndpointAuthMethod.client_secret_basic),
                null,
                Set.of(TokenEndpointAuthMethod.client_secret_basic),
                null,
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
                Duration.ofSeconds(3600));
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

    public static Client publicClient() {
        return new Client(
                "public",
                null,
                Set.of("http://rp1.example.com", "http://rp2.example.com"),
                Set.of(
                        Set.of(ResponseType.code),
                        Set.of(ResponseType.token),
                        Set.of(ResponseType.id_token),
                        Set.of(ResponseType.none),
                        Set.of(ResponseType.code, ResponseType.token),
                        Set.of(ResponseType.code, ResponseType.id_token),
                        Set.of(ResponseType.id_token, ResponseType.token),
                        Set.of(ResponseType.code, ResponseType.token, ResponseType.id_token)),
                ApplicationType.WEB,
                Set.of(
                        GrantType.authorization_code,
                        GrantType.implicit,
                        GrantType.password,
                        GrantType.refresh_token),
                null,
                null,
                null,
                "rs:scope1 rs:scope2 openid",
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                TokenEndpointAuthMethod.none,
                "ES256",
                null,
                null,
                false,
                List.of("acr1"),
                null);
    }

    public static Client confidentialClient() {
        return new Client(
                "confidential",
                "secret",
                Set.of("http://rp1.example.com", "http://rp2.example.com"),
                Set.of(
                        Set.of(ResponseType.code),
                        Set.of(ResponseType.token),
                        Set.of(ResponseType.id_token),
                        Set.of(ResponseType.none),
                        Set.of(ResponseType.code, ResponseType.token),
                        Set.of(ResponseType.code, ResponseType.id_token),
                        Set.of(ResponseType.id_token, ResponseType.token),
                        Set.of(ResponseType.code, ResponseType.token, ResponseType.id_token)),
                ApplicationType.WEB,
                Set.of(
                        GrantType.authorization_code,
                        GrantType.implicit,
                        GrantType.password,
                        GrantType.client_credentials,
                        GrantType.refresh_token),
                null,
                null,
                null,
                "rs:scope1 rs:scope2 openid",
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                TokenEndpointAuthMethod.client_secret_basic,
                null,
                SigningAlgorithm.ES256,
                null,
                null,
                List.of("acr1"),
                null);
    }

    public static Client noGrantTypeClient() {
        return new Client(
                "noGrantTypesClient",
                "clientSecret",
                Set.of("http://rp1.example.com"),
                Set.of(
                        Set.of(ResponseType.code),
                        Set.of(ResponseType.token),
                        Set.of(ResponseType.id_token),
                        Set.of(ResponseType.none),
                        Set.of(ResponseType.code, ResponseType.token),
                        Set.of(ResponseType.code, ResponseType.id_token),
                        Set.of(ResponseType.id_token, ResponseType.token),
                        Set.of(ResponseType.code, ResponseType.token, ResponseType.id_token)),
                ApplicationType.WEB,
                Set.of(),
                null,
                null,
                null,
                "scope1 scope2",
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                TokenEndpointAuthMethod.client_secret_basic,
                null,
                SigningAlgorithm.ES256,
                null,
                null,
                List.of("acr1"),
                null);
    }

    public static Client authorizationCodeClient() {
        return new Client(
                "authorizationCodeClient",
                "secret",
                Set.of("http://rp1.example.com", "http://rp2.example.com"),
                Set.of(Set.of(ResponseType.code)),
                ApplicationType.WEB,
                Set.of(GrantType.authorization_code),
                null,
                null,
                null,
                "rs:scope1 rs:scope2 openid",
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                TokenEndpointAuthMethod.client_secret_basic,
                null,
                SigningAlgorithm.ES256,
                null,
                null,
                List.of("acr1"),
                null);
    }

    public static Client noResponseTypeClient() {
        return new Client(
                "noResponseTypeClient",
                "secret",
                Set.of("http://rp1.example.com", "http://rp2.example.com"),
                Set.of(),
                ApplicationType.WEB,
                Set.of(
                        GrantType.authorization_code,
                        GrantType.implicit,
                        GrantType.password,
                        GrantType.client_credentials,
                        GrantType.refresh_token),
                null,
                null,
                null,
                "rs:scope1 rs:scope2 openid",
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                TokenEndpointAuthMethod.client_secret_basic,
                null,
                SigningAlgorithm.ES256,
                null,
                null,
                List.of("acr1"),
                null);
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
