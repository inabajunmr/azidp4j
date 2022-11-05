package org.azidp4j.client;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Set;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.request.ResponseType;
import org.junit.jupiter.api.Test;

class InternalClientValidatorTest {

    private final InternalClientValidator sut =
            new InternalClientValidator(Fixtures.azIdPConfig("kid"));

    @Test
    void validate_NotSupportedScope() {
        // setup
        var client =
                new Client(
                        "confidential",
                        "secret",
                        Set.of("https://rp1.example.com", "https://rp2.example.com"),
                        Set.of(
                                Set.of(
                                        ResponseType.code,
                                        ResponseType.token,
                                        ResponseType.id_token,
                                        ResponseType.none)),
                        ApplicationType.WEB,
                        Set.of(
                                GrantType.authorization_code,
                                GrantType.implicit,
                                GrantType.password,
                                GrantType.client_credentials,
                                GrantType.refresh_token),
                        null,
                        null,
                        null,
                        "unknown",
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        TokenEndpointAuthMethod.client_secret_basic,
                        null,
                        SigningAlgorithm.ES256,
                        null,
                        null,
                        null);

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("unsupported scope", e.getMessage());
        }
    }

    @Test
    void validate_JwksAndJwksUri() {
        // setup
        var client =
                new Client(
                        "confidential",
                        "secret",
                        Set.of("https://rp1.example.com", "https://rp2.example.com"),
                        Set.of(
                                Set.of(
                                        ResponseType.code,
                                        ResponseType.token,
                                        ResponseType.id_token,
                                        ResponseType.none)),
                        ApplicationType.WEB,
                        Set.of(
                                GrantType.authorization_code,
                                GrantType.implicit,
                                GrantType.password,
                                GrantType.client_credentials,
                                GrantType.refresh_token),
                        null,
                        null,
                        null,
                        "rs:scope1 rs:scope2 openid",
                        null,
                        null,
                        null,
                        "https://example.com/jwks", // target
                        Fixtures.jwkSet(), // target
                        null,
                        null,
                        TokenEndpointAuthMethod.client_secret_basic,
                        null,
                        SigningAlgorithm.ES256,
                        null,
                        null,
                        null);

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("jwks and jwksUri", e.getMessage());
        }
    }

    @Test
    void validate_tokenEndpointAuthMethodIsNullButClientCredentials() {
        // setup
        var client =
                new Client(
                        "confidential",
                        "secret",
                        Set.of("https://rp1.example.com", "https://rp2.example.com"),
                        Set.of(),
                        ApplicationType.WEB,
                        Set.of(GrantType.client_credentials), // target
                        null,
                        null,
                        null,
                        "rs:scope1 rs:scope2 openid",
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        TokenEndpointAuthMethod.none, // target
                        null,
                        SigningAlgorithm.ES256,
                        null,
                        null,
                        null);

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(
                    "tokenEndpoint doesn't required authentication but client_credential supported",
                    e.getMessage());
        }
    }

    @Test
    void validate_WebApplicationAndImplicitButRedirectUriIsHttp() {
        // setup
        var client =
                new Client(
                        "confidential",
                        "secret",
                        Set.of("http://rp1.example.com" /* target */, "https://rp2.example.com"),
                        Set.of(),
                        ApplicationType.WEB, // target
                        Set.of(GrantType.implicit), // target
                        null,
                        null,
                        null,
                        "rs:scope1 rs:scope2 openid",
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        TokenEndpointAuthMethod.client_secret_basic,
                        null,
                        SigningAlgorithm.ES256,
                        null,
                        null,
                        null);

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("web application can't supports http and localhost", e.getMessage());
        }
    }

    @Test
    void validate_WebApplicationAndImplicitButRedirectUriIsLocalhost() {
        // setup
        var client =
                new Client(
                        "confidential",
                        "secret",
                        Set.of("https://localhost:8080" /* target */, "https://rp2.example.com"),
                        Set.of(),
                        ApplicationType.WEB, // target
                        Set.of(GrantType.implicit), // target
                        null,
                        null,
                        null,
                        "rs:scope1 rs:scope2 openid",
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        TokenEndpointAuthMethod.client_secret_basic,
                        null,
                        SigningAlgorithm.ES256,
                        null,
                        null,
                        null);

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("web application can't supports http and localhost", e.getMessage());
        }
    }

    @Test
    void validate_NativeApplicationButRedirectUriIsHttps() {
        // setup
        var client =
                new Client(
                        "confidential",
                        "secret",
                        Set.of("https://example.com" /* target */, "http://localhost:8080"),
                        Set.of(),
                        ApplicationType.NATIVE, // target
                        Set.of(GrantType.implicit),
                        null,
                        null,
                        null,
                        "rs:scope1 rs:scope2 openid",
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        TokenEndpointAuthMethod.client_secret_basic,
                        null,
                        SigningAlgorithm.ES256,
                        null,
                        null,
                        null);

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("native client can't support https", e.getMessage());
        }
    }

    @Test
    void validate_NativeApplicationButRedirectUriIsNotLocalhost() {
        // setup
        var client =
                new Client(
                        "confidential",
                        "secret",
                        Set.of("http://example.com" /* target */, "http://localhost:8080"),
                        Set.of(),
                        ApplicationType.NATIVE, // target
                        Set.of(GrantType.implicit),
                        null,
                        null,
                        null,
                        "rs:scope1 rs:scope2 openid",
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        TokenEndpointAuthMethod.client_secret_basic,
                        null,
                        SigningAlgorithm.ES256,
                        null,
                        null,
                        null);

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(
                    "native client can't supports http schema except for localhost",
                    e.getMessage());
        }
    }

    @Test
    void validate_IllegalInitiateLoginUri() {
        // setup
        var client =
                new Client(
                        "confidential",
                        "secret",
                        Set.of("https://example.com"),
                        Set.of(),
                        ApplicationType.WEB,
                        Set.of(GrantType.authorization_code),
                        null,
                        null,
                        null,
                        "rs:scope1 rs:scope2 openid",
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        TokenEndpointAuthMethod.client_secret_basic,
                        null,
                        SigningAlgorithm.ES256,
                        null,
                        null,
                        "illegal"); // target

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("illegal initiateLoginUri", e.getMessage());
        }
    }

    @Test
    void validate_IllegalMaxAge() {
        // setup
        var client =
                new Client(
                        "confidential",
                        "secret",
                        Set.of("https://example.com"),
                        Set.of(),
                        ApplicationType.WEB,
                        Set.of(GrantType.authorization_code),
                        null,
                        null,
                        null,
                        "rs:scope1 rs:scope2 openid",
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        TokenEndpointAuthMethod.client_secret_basic,
                        null,
                        SigningAlgorithm.ES256,
                        -1L, // target
                        null,
                        "https://example.com");

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("defaultMaxAge must be positive", e.getMessage());
        }
    }
}