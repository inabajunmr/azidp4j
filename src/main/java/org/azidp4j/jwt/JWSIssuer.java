package org.azidp4j.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.azidp4j.jwt.jwks.JWKSupplier;

import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.util.Map;

public class JWSIssuer {

    private final JWKSupplier jwkSupplier;

    public JWSIssuer(JWKSupplier jwkSupplier) {
        this.jwkSupplier = jwkSupplier;
    }

    public JWSObject issue(Map<String, Object> payload) {

        try {
            ECKey ecJWK = (ECKey)jwkSupplier.jwks().getKeys().get(0);
            JWSSigner signer = new ECDSASigner(ecJWK);
            JWSObject jwsObject = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(ecJWK.getKeyID()).build(), new Payload(payload));
            jwsObject.sign(signer);
            return jwsObject;
        }catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
}
