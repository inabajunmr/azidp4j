package org.azidp4j.client;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Set;
import org.junit.jupiter.api.Test;

class TokenEndpointAuthSigningAlgExtractorTest {

    @Test
    void success() {
        // exercise
        var actual =
                TokenEndpointAuthSigningAlgExtractor.extract(
                        "ES256",
                        TokenEndpointAuthMethod.private_key_jwt,
                        Set.of(SigningAlgorithm.RS256, SigningAlgorithm.ES256));

        // verify
        assertEquals(SigningAlgorithm.ES256, actual);
    }

    @Test
    void default_JWT() {
        // exercise
        var actual =
                TokenEndpointAuthSigningAlgExtractor.extract(
                        null,
                        TokenEndpointAuthMethod.private_key_jwt,
                        Set.of(SigningAlgorithm.RS256, SigningAlgorithm.ES256));

        // verify
        // default is RS256
        assertEquals(SigningAlgorithm.RS256, actual);
    }

    @Test
    void default_NotJWT() {
        // exercise
        var actual =
                TokenEndpointAuthSigningAlgExtractor.extract(
                        null,
                        TokenEndpointAuthMethod.client_secret_basic,
                        Set.of(SigningAlgorithm.RS256, SigningAlgorithm.ES256));

        // verify
        assertNull(actual);
    }

    @Test
    void default_TokenEndpointAuthSigningAlgIsUnsupported() {
        // exercise
        var actual =
                TokenEndpointAuthSigningAlgExtractor.extract(
                        "RS256", TokenEndpointAuthMethod.client_secret_basic, null);

        // verify
        assertNull(actual);
    }

    @Test
    void extract_IllegalValue() {
        // exercise
        try {
            TokenEndpointAuthSigningAlgExtractor.extract(
                    "illegal",
                    TokenEndpointAuthMethod.client_secret_basic,
                    Set.of(SigningAlgorithm.RS256));
            fail();
        } catch (IllegalArgumentException e) {
            // verify
            assertEquals("illegal is not supported", e.getMessage());
        }
    }
}
