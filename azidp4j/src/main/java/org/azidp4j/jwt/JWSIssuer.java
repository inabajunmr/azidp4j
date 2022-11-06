package org.azidp4j.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.util.Map;

public class JWSIssuer {

    private final JWKSet jwkSet;

    public JWSIssuer(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    public JWSObject issue(String kid, String type, Map<String, Object> payload) {
        try {
            var jwk = jwkSet.getKeyByKeyId(kid);
            if (jwk == null) {
                throw new AssertionError();
            }
            if (jwk instanceof ECKey ecJWK) {
                JWSSigner signer = new ECDSASigner(ecJWK);
                JWSObject jwsObject;
                if (type == null) {
                    jwsObject =
                            new JWSObject(
                                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                                            .keyID(ecJWK.getKeyID())
                                            .build(),
                                    new Payload(payload));
                } else {
                    jwsObject =
                            new JWSObject(
                                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                                            .keyID(ecJWK.getKeyID())
                                            .type(new JOSEObjectType(type))
                                            .build(),
                                    new Payload(payload));
                }
                jwsObject.sign(signer);
                return jwsObject;
            } else if (jwk instanceof RSAKey rsaJWK) {
                JWSSigner signer = new RSASSASigner(rsaJWK);
                JWSObject jwsObject;
                if (type == null) {
                    jwsObject =
                            new JWSObject(
                                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                                            .keyID(rsaJWK.getKeyID())
                                            .build(),
                                    new Payload(payload));
                } else {
                    jwsObject =
                            new JWSObject(
                                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                                            .keyID(rsaJWK.getKeyID())
                                            .type(new JOSEObjectType(type))
                                            .build(),
                                    new Payload(payload));
                }
                jwsObject.sign(signer);
                return jwsObject;
            } else {
                throw new AssertionError("not supported key.");
            }
        } catch (JOSEException e) {
            throw new AssertionError(e);
        }
    }
}
