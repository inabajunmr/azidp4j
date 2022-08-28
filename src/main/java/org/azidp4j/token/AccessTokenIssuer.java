package org.azidp4j.token;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWKSet;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.jwt.JWSIssuer;

import java.util.Map;
import java.util.UUID;

public class AccessTokenIssuer {

    private final AzIdPConfig config;

    private final JWSIssuer jwsIssuer;


    public AccessTokenIssuer(AzIdPConfig config, JWKSet jwkSet) {
        this.config = config;
        this.jwsIssuer = new JWSIssuer(jwkSet);
    }

    JWSObject issue(String sub, String aud, String clientId, String scope) {
        var jti = UUID.randomUUID().toString();
        Map<String, Object> claims = Map.of(
                "iss", "", "sub", sub, "aud", aud,
                "exp", 0, "iat", 0,
                "jti", jti, "client_id", clientId, "scope", scope);
        return jwsIssuer.issue(config.accessTokenKid, claims);
    }
}
