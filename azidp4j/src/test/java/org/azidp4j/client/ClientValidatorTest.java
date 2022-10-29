package org.azidp4j.client;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Set;
import org.azidp4j.authorize.request.ResponseType;
import org.junit.jupiter.api.Test;

class ClientValidatorTest {

    private final ClientValidator sut = new ClientValidator();

    @Test
    void validate_JwksAndJwksUri() {
        // setup
        var client =
                new Client(
                        "confidential",
                        "secret",
                        Set.of("http://rp1.example.com", "http://rp2.example.com"),
                        Set.of(
                                ResponseType.code,
                                ResponseType.token,
                                ResponseType.id_token,
                                ResponseType.none),
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
                        "jwks", // target
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
        }
    }

    @Test
    void validate_tokenEndpointAuthMethodIsNullButClientCredentials() {
        // setup
        var client =
                new Client(
                        "confidential",
                        "secret",
                        Set.of("http://rp1.example.com", "http://rp2.example.com"),
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
        }
    }

    @Test
    void validate_IllegalInitiateLoginUri() {
        // setup
        var client =
                new Client(
                        "confidential",
                        "secret",
                        Set.of("http://example.com", "http://localhost:8080"),
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
        }
    }

    @Test
    void validate_IllegalMaxAge() {
        // setup
        var client =
                new Client(
                        "confidential",
                        "secret",
                        Set.of("http://example.com", "http://localhost:8080"),
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
        }
    }
}
