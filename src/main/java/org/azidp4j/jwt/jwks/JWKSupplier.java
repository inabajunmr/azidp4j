package org.azidp4j.jwt.jwks;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;


public class JWKSupplier {

    private final JWKSet jwkSet;

    public JWKSupplier() {
        try {
            var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
            jwkSet = new JWKSet(key);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    public JWKSet jwks() {
        return jwkSet;
    }

    public JWKSet publicJwks() {
        return jwkSet.toPublicJWKSet();
    }
}
