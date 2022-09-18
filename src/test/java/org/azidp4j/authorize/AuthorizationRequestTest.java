package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import org.junit.jupiter.api.Test;

class AuthorizationRequestTest {

    @Test
    void removePrompt() {
        assertNull(
                new AuthorizationRequest("user", Map.of())
                        .removePrompt("login")
                        .queryParameters
                        .get("prompt"));
        ;
        assertNull(
                new AuthorizationRequest("user", Map.of("prompt", "login"))
                        .removePrompt("login")
                        .queryParameters
                        .get("prompt"));
        ;
        assertEquals(
                "consent",
                new AuthorizationRequest("user", Map.of("prompt", "login consent"))
                        .removePrompt("login")
                        .queryParameters
                        .get("prompt"));
        ;
    }
}
