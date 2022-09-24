package org.azidp4j;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import java.text.ParseException;

public class IdTokenAssert {
    public static void assertIdToken(
            String idToken,
            ECKey key,
            String sub,
            String aud,
            String iss,
            long exp,
            long iat,
            long authTime,
            String nonce,
            String accessToken,
            String authorizationCode)
            throws ParseException, JOSEException {
        var parsedIdToken = JWSObject.parse(idToken);
        // verify signature
        assertTrue(parsedIdToken.verify(new ECDSAVerifier(key)));
        assertEquals(parsedIdToken.getHeader().getAlgorithm(), JWSAlgorithm.ES256);
        // verify claims
        var payload = parsedIdToken.getPayload().toJSONObject();
        assertEquals(payload.get("sub"), sub);
        assertEquals(payload.get("aud"), aud);
        assertNotNull(payload.get("jti"));
        assertEquals(payload.get("iss"), iss);
        assertTrue((long) payload.get("exp") > exp - 10);
        assertTrue((long) payload.get("exp") < exp + 10);
        assertTrue((long) payload.get("iat") > iat - 10);
        assertTrue((long) payload.get("iat") < iat + 10);
        assertTrue((long) payload.get("auth_time") > authTime - 10);
        assertTrue((long) payload.get("auth_time") < authTime + 10);
        assertEquals(nonce, payload.get("nonce"));
        if (accessToken != null) {
            assertNotNull(payload.get("at_hash"));
        }
        if (authorizationCode != null) {
            assertNotNull(payload.get("c_hash"));
        }
    }
}
