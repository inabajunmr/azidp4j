package org.azidp4j.token.idtoken;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWKSet;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.jwt.JWSIssuer;

public class IDTokenIssuer {

    private final AzIdPConfig config;

    private final JWSIssuer jwsIssuer;

    public IDTokenIssuer(AzIdPConfig config, JWKSet jwkSet) {
        this.config = config;
        this.jwsIssuer = new JWSIssuer(jwkSet);
    }

    public JWSObject issue(String sub, String clientId, int maxAge, String nonce) {
        var jti = UUID.randomUUID().toString();
        Map<String, Object> claims =
                Map.of(
                        "iss",
                        config.issuer,
                        "sub",
                        sub,
                        "aud",
                        clientId,
                        "exp",
                        Instant.now().getEpochSecond() + config.idTokenExpirationSec,
                        "iat",
                        Instant.now().getEpochSecond(),
                        "jti",
                        jti,
                        "auth_time",
                        Instant.now().getEpochSecond() + maxAge,
                        "nonce",
                        nonce);
        return jwsIssuer.issue(config.idTokenKid, claims);
    }
}
