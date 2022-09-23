package org.azidp4j;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import java.text.ParseException;
import java.util.List;

public class AccessTokenAssert {

    public static void assertAccessToken(
            String accessToken,
            ECKey key,
            String sub,
            String aud,
            String clientId,
            String scope,
            String iss,
            long exp,
            long iat)
            throws ParseException, JOSEException {

        var parsedAccessToken = JWSObject.parse(accessToken);
        // verify signature
        assertTrue(parsedAccessToken.verify(new ECDSAVerifier(key)));
        assertEquals(parsedAccessToken.getHeader().getAlgorithm(), JWSAlgorithm.ES256);
        assertEquals(parsedAccessToken.getHeader().getType().getType(), "at+JWT");
        // verify claims
        var payload = parsedAccessToken.getPayload().toJSONObject();
        assertEquals(payload.get("sub"), sub);
        assertEquals(payload.get("aud"), List.of(aud));
        assertEquals(payload.get("client_id"), clientId);
        assertEquals(payload.get("scope"), scope);
        assertNotNull(payload.get("jti"));
        assertEquals(payload.get("iss"), iss);
        assertTrue((long) Integer.parseInt(payload.get("exp").toString()) > exp - 10);
        assertTrue((long) Integer.parseInt(payload.get("exp").toString()) < exp + 10);
        assertTrue((long) Integer.parseInt(payload.get("iat").toString()) > iat - 10);
        assertTrue((long) Integer.parseInt(payload.get("iat").toString()) < iat + 10);
    }
}
