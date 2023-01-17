package org.azidp4j.client;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Set;
import org.junit.jupiter.api.Test;

class TokenEndpointAuthMethodExtractorTest {

    @Test
    void extract_Success() {
        // exercise
        var actual =
                TokenEndpointAuthMethodExtractor.extract(
                        "client_secret_post",
                        Set.of(
                                TokenEndpointAuthMethod.client_secret_post,
                                TokenEndpointAuthMethod.client_secret_basic));

        // verify
        assertEquals(TokenEndpointAuthMethod.client_secret_post, actual);
    }

    @Test
    void extract_Null_Default() {
        // exercise
        var actual =
                TokenEndpointAuthMethodExtractor.extract(
                        null,
                        Set.of(
                                TokenEndpointAuthMethod.client_secret_post,
                                TokenEndpointAuthMethod.client_secret_basic));

        // verify
        assertEquals(TokenEndpointAuthMethod.client_secret_basic, actual);
    }

    @Test
    void extract_TokenEndpointAuthMethodIsUnsupported() {
        // exercise
        var actual = TokenEndpointAuthMethodExtractor.extract("client_secret_post", null);

        // verify
        assertNull(actual);
    }

    @Test
    void extract_IllegalValue() {
        // exercise
        try {
            TokenEndpointAuthMethodExtractor.extract(
                    "illegal",
                    Set.of(
                            TokenEndpointAuthMethod.private_key_jwt,
                            TokenEndpointAuthMethod.client_secret_basic));
            fail();
        } catch (IllegalArgumentException e) {
            // verify
            assertEquals("illegal is not supported", e.getMessage());
        }
    }
}
