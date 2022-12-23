package org.azidp4j;

import static org.junit.jupiter.api.Assertions.*;

import org.azidp4j.token.accesstoken.AccessToken;

public class AccessTokenAssert {

    public static void assertAccessToken(
            AccessToken actual, String sub, String aud, String clientId, String scope, long exp) {

        assertEquals(actual.sub, sub);
        assertEquals(actual.audience.size(), 1);
        assertEquals(actual.audience.stream().findAny().get(), aud);
        assertEquals(actual.clientId, clientId);
        assertEquals(actual.scope, scope);
        assertTrue(actual.expiresAtEpochSec > exp - 10);
        assertTrue(actual.expiresAtEpochSec < exp + 10);
    }
}
