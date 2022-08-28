package org.azidp4j.jwt;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.util.Map;
import org.junit.jupiter.api.Test;

class JWSIssuerTest {

    @Test
    void issue() throws JOSEException {
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var sut = new JWSIssuer(jwks);
        var jws = sut.issue(key.getKeyID(), Map.of("test", "abc"));
        var payload = jws.getPayload().toJSONObject();
        assertEquals(payload.get("test"), "abc");

        // verify signature
        var jwk = jwks.toPublicJWKSet().getKeyByKeyId(jws.getHeader().getKeyID());
        var verifier = new ECDSAVerifier((ECKey) jwk);
        assertTrue(jws.verify(verifier));
    }
}
