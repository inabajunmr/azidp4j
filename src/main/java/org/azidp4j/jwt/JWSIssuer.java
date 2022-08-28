package org.azidp4j.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;

import java.util.Map;

public class JWSIssuer {

    private final JWKSet jwkSet;

    public JWSIssuer(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    public JWSObject issue(String kid, Map<String, Object> payload) {

        try {
            var jwk = jwkSet.getKeyByKeyId(kid);
            if(jwk instanceof  ECKey) {
                ECKey ecJWK = (ECKey)jwk;
                JWSSigner signer = new ECDSASigner(ecJWK);
                JWSObject jwsObject = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .keyID(ecJWK.getKeyID()).build(), new Payload(payload));
                jwsObject.sign(signer);
                return jwsObject;
            } else {
                throw new RuntimeException("not supported key.");
            }
        }catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
}
