package org.azidp4j;

import java.util.Set;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.Client;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.SigningAlgorithm;
import org.azidp4j.client.TokenEndpointAuthMethod;

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
                Set.of("openid", "scope1", "scope2", "default"),
                Set.of("openid", "scope1"),
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
                Set.of(ResponseType.code, ResponseType.token),
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
                SigningAlgorithm.ES256);
    }

    public static Client confidentialClient() {
        return new Client(
                "confidential",
                "secret",
                Set.of("http://rp1.example.com", "http://rp2.example.com"),
                Set.of(ResponseType.code, ResponseType.token),
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
                SigningAlgorithm.ES256);
    }
}
