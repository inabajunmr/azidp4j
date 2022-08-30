package org.azidp4j.token;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWKSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.jwt.JWSIssuer;

public class AccessTokenIssuer {

    private final AzIdPConfig config;

    private final JWSIssuer jwsIssuer;

    public AccessTokenIssuer(AzIdPConfig config, JWKSet jwkSet) {
        this.config = config;
        this.jwsIssuer = new JWSIssuer(jwkSet);
    }

    JWSObject issue(String sub, Set<String> aud, String clientId, String scope) {
        var jti = UUID.randomUUID().toString();
        Map<String, Object> claims =
                Map.of(
                        "iss",
                        "",
                        "sub",
                        sub,
                        "aud",
                        aud,
                        "exp",
                        0,
                        "iat",
                        0,
                        "jti",
                        jti,
                        "client_id",
                        clientId,
                        "scope",
                        scope);
        return jwsIssuer.issue(config.accessTokenKid, claims);
    }
}
