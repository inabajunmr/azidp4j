package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AuthorizationRequestTest {

    @Test
    void removePrompt() {
        assertNull(
                new AuthorizationRequest("user", Instant.now().getEpochSecond(), Map.of())
                        .removePrompt("login")
                        .queryParameters
                        .get("prompt"));
        ;
        assertNull(
                new AuthorizationRequest(
                                "user", Instant.now().getEpochSecond(), Map.of("prompt", "login"))
                        .removePrompt("login")
                        .queryParameters
                        .get("prompt"));
        ;
        assertEquals(
                "consent",
                new AuthorizationRequest(
                                "user",
                                Instant.now().getEpochSecond(),
                                Map.of("prompt", "login consent"))
                        .removePrompt("login")
                        .queryParameters
                        .get("prompt"));
        ;
    }
}