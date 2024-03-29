package org.azidp4j.client;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.request.ResponseMode;
import org.azidp4j.authorize.request.ResponseType;
import org.junit.jupiter.api.Test;

class InternalClientValidatorTest {

    private final InternalClientValidator sut = new InternalClientValidator(Fixtures.azIdPConfig());

    @Test
    void validate_NotSupportedGrantType() {

        // setup
        var config =
                new AzIdPConfig(
                        "http://localhost:8080",
                        Set.of("openid", "rs:scope1", "rs:scope2", "rs:scope3", "default"),
                        Set.of("openid", "rs:scope1"),
                        Set.of(TokenEndpointAuthMethod.client_secret_basic),
                        null,
                        Set.of(TokenEndpointAuthMethod.client_secret_basic),
                        null,
                        Set.of(TokenEndpointAuthMethod.client_secret_basic),
                        null,
                        Set.of(
                                GrantType.authorization_code,
                                GrantType.implicit,
                                // GrantType.password, // target
                                GrantType.client_credentials,
                                GrantType.refresh_token),
                        Set.of(
                                Set.of(ResponseType.code),
                                Set.of(ResponseType.token),
                                Set.of(ResponseType.id_token),
                                Set.of(ResponseType.code, ResponseType.token),
                                Set.of(ResponseType.code, ResponseType.id_token),
                                Set.of(ResponseType.token, ResponseType.id_token),
                                Set.of(
                                        ResponseType.code,
                                        ResponseType.token,
                                        ResponseType.id_token)),
                        Set.of(ResponseMode.query, ResponseMode.fragment),
                        Set.of(),
                        List.of("acr"),
                        Duration.ofSeconds(3600),
                        Duration.ofSeconds(600),
                        Duration.ofSeconds(604800),
                        Duration.ofSeconds(3600),
                        null);
        var sut = new InternalClientValidator(config);
        var client =
                Fixtures.confidentialClient()
                        .grantTypes(
                                Set.of(
                                        GrantType.authorization_code,
                                        GrantType.implicit,
                                        GrantType.password,
                                        GrantType.client_credentials,
                                        GrantType.refresh_token))
                        .build();

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("unsupported grant types", e.getMessage());
        }
    }

    @Test
    void validate_NotSupportedResponseTypes() {
        // setup
        var client =
                Fixtures.confidentialClient()
                        .responseTypes(
                                Set.of(
                                        Set.of(
                                                ResponseType.code,
                                                ResponseType.token,
                                                ResponseType.id_token,
                                                ResponseType.none) // target
                                        ))
                        .build();

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("unsupported response types", e.getMessage());
        }
    }

    @Test
    void validate_NotSupportedScope() {
        // setup
        var client =
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .scope("unknown")
                        .build();

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
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .jwks(Fixtures.jwkSet()) // target
                        .jwksUri("https://example.com/jwks") // target
                        .build();

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("jwks and jwksUri", e.getMessage());
        }
    }

    @Test
    void validate_tokenEndpointAuthMethodIsNoneButClientCredentials() {
        // setup
        var client =
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .grantTypes(Set.of(GrantType.client_credentials)) // target
                        .tokenEndpointAuthMethod(TokenEndpointAuthMethod.none) // target
                        .build();

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
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .applicationType(ApplicationType.WEB) // target
                        .grantTypes(Set.of(GrantType.implicit)) // target
                        .redirectUris(Set.of("http://example.com")) // target
                        .build();

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
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .applicationType(ApplicationType.WEB) // target
                        .grantTypes(Set.of(GrantType.implicit)) // target
                        .redirectUris(Set.of("https://localhost:8080")) // target
                        .build();

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
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .applicationType(ApplicationType.NATIVE) // target
                        .grantTypes(Set.of(GrantType.implicit))
                        .redirectUris(
                                Set.of(
                                        "https://example.com", // target
                                        "http://localhost:8080"))
                        .build();

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
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .applicationType(ApplicationType.NATIVE) // target
                        .grantTypes(Set.of(GrantType.implicit))
                        .redirectUris(
                                Set.of(
                                        "http://example.com", // target
                                        "http://localhost:8080"))
                        .build();

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
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .applicationType(ApplicationType.WEB)
                        .grantTypes(Set.of(GrantType.implicit))
                        .initiateLoginUri("illegal") // target
                        .build();

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
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .applicationType(ApplicationType.WEB)
                        .grantTypes(Set.of(GrantType.implicit))
                        .defaultMaxAge(-1L) // target
                        .build();

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("defaultMaxAge must be positive", e.getMessage());
        }
    }

    @Test
    void validate_UnsupportedAcr() {
        // setup
        var client =
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .applicationType(ApplicationType.WEB)
                        .grantTypes(Set.of(GrantType.implicit))
                        .defaultAcrValues(List.of("acr1", "unsupported")) // target
                        .build();

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("defaultAcrValues doesn't support at acrValuesSupported", e.getMessage());
        }
    }

    @Test
    void validate_TokenEndpointAuth_Unsupported() {
        // setup
        var client =
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .applicationType(ApplicationType.WEB)
                        .grantTypes(Set.of(GrantType.implicit))
                        .tokenEndpointAuthMethod(TokenEndpointAuthMethod.client_secret_post)
                        .build();

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("client_secret_post is not supported", e.getMessage());
        }
    }

    @Test
    void validate_TokenEndpointAuthSigningAlg_TokenEndpointAuthMethodNotRequiresSigningAlg() {
        // setup
        var client =
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .applicationType(ApplicationType.WEB)
                        .grantTypes(Set.of(GrantType.implicit))
                        .tokenEndpointAuthMethod(TokenEndpointAuthMethod.client_secret_basic)
                        .tokenEndpointAuthSigningAlg(SigningAlgorithm.RS256)
                        .build();

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(
                    "tokenEndpointAuthMethod client_secret_basic doesn't required"
                            + " tokenEndpointAuthSigningAlg",
                    e.getMessage());
        }
    }

    @Test
    void validate_TokenEndpointAuthSigningAlg_SigningAlgNotSupported() {
        // setup
        var client =
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .applicationType(ApplicationType.WEB)
                        .grantTypes(Set.of(GrantType.implicit))
                        .tokenEndpointAuthMethod(TokenEndpointAuthMethod.private_key_jwt)
                        .tokenEndpointAuthSigningAlg(SigningAlgorithm.ES256)
                        .build();

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("ES256 is not supported", e.getMessage());
        }
    }

    @Test
    void validate_IntrospectionEndpointAuth_Unsupported() {
        // setup
        var client =
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .applicationType(ApplicationType.WEB)
                        .grantTypes(Set.of(GrantType.implicit))
                        .introspectionEndpointAuthMethod(TokenEndpointAuthMethod.client_secret_post)
                        .build();

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("client_secret_post is not supported", e.getMessage());
        }
    }

    @Test
    void
            validate_IntrospectionEndpointAuthSigningAlg_IntrospectionEndpointAuthMethodNotRequiresSigningAlg() {
        // setup
        var client =
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .applicationType(ApplicationType.WEB)
                        .grantTypes(Set.of(GrantType.implicit))
                        .introspectionEndpointAuthMethod(
                                TokenEndpointAuthMethod.client_secret_basic)
                        .introspectionEndpointAuthSigningAlg(SigningAlgorithm.RS256)
                        .build();

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(
                    "introspectionEndpointAuthMethod client_secret_basic doesn't required"
                            + " introspectionEndpointAuthSigningAlg",
                    e.getMessage());
        }
    }

    @Test
    void validate_IntrospectionEndpointAuthSigningAlg_SigningAlgNotSupported() {
        // setup
        var client =
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .applicationType(ApplicationType.WEB)
                        .grantTypes(Set.of(GrantType.implicit))
                        .introspectionEndpointAuthMethod(TokenEndpointAuthMethod.private_key_jwt)
                        .introspectionEndpointAuthSigningAlg(SigningAlgorithm.RS256)
                        .build();

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("RS256 is not supported", e.getMessage());
        }
    }

    @Test
    void validate_RevocationEndpointAuth_Unsupported() {
        // setup
        var client =
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .applicationType(ApplicationType.WEB)
                        .grantTypes(Set.of(GrantType.implicit))
                        .revocationEndpointAuthMethod(TokenEndpointAuthMethod.client_secret_post)
                        .build();

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("client_secret_post is not supported", e.getMessage());
        }
    }

    @Test
    void
            validate_RevocationEndpointAuthSigningAlg_RevocationEndpointAuthMethodNotRequiresSigningAlg() {
        // setup
        var client =
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .applicationType(ApplicationType.WEB)
                        .grantTypes(Set.of(GrantType.implicit))
                        .revocationEndpointAuthMethod(TokenEndpointAuthMethod.client_secret_basic)
                        .revocationEndpointAuthSigningAlg(SigningAlgorithm.RS256)
                        .build();

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(
                    "revocationEndpointAuthMethod client_secret_basic doesn't required"
                            + " revocationEndpointAuthSigningAlg",
                    e.getMessage());
        }
    }

    @Test
    void validate_RevocationEndpointAuthSigningAlg_SigningAlgNotSupported() {
        // setup
        var client =
                Fixtures.confidentialClient()
                        .responseTypes(Set.of(Set.of(ResponseType.code)))
                        .applicationType(ApplicationType.WEB)
                        .grantTypes(Set.of(GrantType.implicit))
                        .revocationEndpointAuthMethod(TokenEndpointAuthMethod.private_key_jwt)
                        .revocationEndpointAuthSigningAlg(SigningAlgorithm.ES256)
                        .build();

        // exercise
        try {
            sut.validate(client);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("ES256 is not supported", e.getMessage());
        }
    }
}
