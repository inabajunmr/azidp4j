package org.azidp4j;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.azidp4j.token.accesstoken.AccessToken;

public class AccessTokenAssert {

    public static void assertAccessToken(
            AccessToken actual, String sub, String aud, String clientId, String scope, long exp) {

        assertEquals(actual.getSub(), sub);
        assertEquals(actual.getAudience().size(), 1);
        assertEquals(actual.getAudience().stream().findAny().get(), aud);
        assertEquals(actual.getClientId(), clientId);
        assertEquals(actual.getScope(), scope);
        assertTrue(actual.getExpiresAtEpochSec() > exp - 10);
        assertTrue(actual.getExpiresAtEpochSec() < exp + 10);
    }
}
