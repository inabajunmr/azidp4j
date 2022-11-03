package org.azidp4j;

import com.nimbusds.jose.jwk.JWKSet;
import java.text.ParseException;
import java.util.Set;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.*;

public class Fixtures {

    public static AzIdPConfig azIdPConfig(String kid) {
        return new AzIdPConfig(
                "http://localhost:8080",
                "http://localhost:8080/authorize",
                "http://localhost:8080/token",
                "http://localhost:8080/.well-known/jwks.json",
                "http://localhost:8080/client",
                "http://localhost:8080/client/{CLIENT_ID}",
                "http://localhost:8080/userinfo",
                Set.of("openid", "rs:scope1", "rs:scope2", "rs:scope3", "default"),
                Set.of("openid", "rs:scope1"),
                kid,
                3600,
                600,
                604800,
                3600);
    }

    public static Client publicClient() {
        return new Client(
                "public",
                null,
                null,
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
                SigningAlgorithm.ES256,
                null,
                null,
                false,
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
