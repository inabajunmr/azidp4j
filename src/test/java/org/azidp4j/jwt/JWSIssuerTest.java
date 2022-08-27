package org.azidp4j.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import org.azidp4j.jwt.jwks.JWKSupplier;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JWSIssuerTest {

    @Test
    void issue() throws JOSEException {
        var jwkSupplier = new JWKSupplier();
        var sut = new JWSIssuer(jwkSupplier);
        var jws = sut.issue(Map.of("test", "abc"));
        var payload = jws.getPayload().toJSONObject();
        assertEquals(payload.get("test"), "abc");

        // verify signature
        var jwk = jwkSupplier.publicJwks().getKeyByKeyId(jws.getHeader().getKeyID());
        var verifier = new ECDSAVerifier((ECKey) jwk);
        assertTrue(jws.verify(verifier));
    }

}