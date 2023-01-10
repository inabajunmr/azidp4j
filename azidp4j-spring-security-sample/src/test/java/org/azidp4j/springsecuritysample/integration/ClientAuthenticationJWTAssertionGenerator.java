package org.azidp4j.springsecuritysample.integration;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import java.time.Instant;
import java.util.Map;

public class ClientAuthenticationJWTAssertionGenerator {

    public static JWSObject getJwsObject(String aud, String clientId) throws JOSEException {
        var assertion =
                new JWSObject(
                        new JWSHeader.Builder(JWSAlgorithm.ES256)
                                .keyID(ClientJWKs.ES256KEY_ID)
                                .build(),
                        new Payload(
                                Map.of(
                                        "iss",
                                        clientId,
                                        "sub",
                                        clientId,
                                        "aud",
                                        aud,
                                        "exp",
                                        Instant.now().getEpochSecond() + 60)));
        JWSSigner signer =
                new ECDSASigner(ClientJWKs.JWKS.getKeyByKeyId(ClientJWKs.ES256KEY_ID).toECKey());
        assertion.sign(signer);
        return assertion;
    }
}
