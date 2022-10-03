package org.azidp4j;

import java.util.Set;

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
                kid,
                kid,
                3600,
                600,
                604800,
                3600);
    }
}
