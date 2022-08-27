package org.azidp4j.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import org.azidp4j.jwt.JWSIssuer;
import org.azidp4j.jwt.jwks.JWKSupplier;

import java.util.Map;
import java.util.UUID;

public class AccessTokenIssuer {

    private final JWSIssuer jwsIssuer;

    public AccessTokenIssuer(JWKSupplier jwkSupplier) {
        this.jwsIssuer = new JWSIssuer(jwkSupplier);
    }

    JWSObject issue(String sub, String aud, String clientId, String scope) {
        var jti = UUID.randomUUID().toString();
        Map<String, Object> claims = Map.of(
                "iss", "", "sub", sub, "aud", aud,
                "exp", 0, "iat", 0,
                "jti", jti, "client_id", clientId, "scope", scope);
        return jwsIssuer.issue(claims);
    }
}
