package org.azidp4j.springsecuritysample.integration;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.util.List;

public class ClientJWKs {

    public static String ES256KEY_ID = "es256key";

    public static String RS256KEY_ID = "rs256key";

    public static JWKSet JWKS;

    static {
        try {
            var es256Key =
                    new ECKeyGenerator(Curve.P_256)
                            .keyID(ES256KEY_ID)
                            .algorithm(new Algorithm("ES256"))
                            .generate();
            var rs256Key =
                    new RSAKeyGenerator(2048)
                            .keyID(RS256KEY_ID)
                            .algorithm(new Algorithm("RS256"))
                            .generate();
            JWKS = new JWKSet(List.of(es256Key, rs256Key));
        } catch (JOSEException ex) {
            throw new AssertionError(ex);
        }
    }
}
