package org.azidp4j.token.idtoken;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.util.List;
import java.util.Map;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.jwt.JWSIssuer;
import org.junit.jupiter.api.Test;

class IDTokenValidatorTest {

    JWK rs256 = new RSAKeyGenerator(2048).keyID("rs").algorithm(new Algorithm("RS256")).generate();

    JWK es256 =
            new ECKeyGenerator(Curve.P_256)
                    .keyID("es")
                    .algorithm(new Algorithm("ES256"))
                    .generate();

    JWKSet jwks = new JWKSet(List.of(rs256, es256));

    JWSIssuer jwsIssuer = new JWSIssuer(jwks);

    AzIdPConfig config = Fixtures.azIdPConfig();
    IDTokenValidator sut = new IDTokenValidator(config, jwks);

    IDTokenValidatorTest() throws JOSEException {}

    @Test
    void validateForIdTokenHint_Success() {
        var client = Fixtures.confidentialClient().build();
        var jws =
                new JWSIssuer(jwks)
                        .issue(
                                "es",
                                null,
                                Map.of(
                                        "iss",
                                        config.issuer,
                                        "aud",
                                        client.clientId,
                                        "azp",
                                        client.clientId));
        sut.validateForIdTokenHint(jws.serialize(), client);
    }

    @Test
    void validateForIdTokenHint_InvalidJwt() {
        try {
            sut.validateForIdTokenHint("invalid", null);
            fail();
        } catch (InvalidIDTokenException e) {
            assertEquals(
                    "Invalid serialized unsecured/JWS/JWE object: Missing part delimiters",
                    e.getMessage());
        }
    }

    @Test
    void validateForIdTokenHint_UnknownKid() {
        try {
            JWK es256 =
                    new ECKeyGenerator(Curve.P_256)
                            .keyID("unknown")
                            .algorithm(new Algorithm("ES256"))
                            .generate();
            JWKSet jwks = new JWKSet(List.of(es256));
            var jws = new JWSIssuer(jwks).issue("unknown", null, Map.of());
            sut.validateForIdTokenHint(jws.serialize(), null);
            fail();
        } catch (InvalidIDTokenException e) {
            assertEquals("Key:unknown is not found", e.getMessage());
        } catch (JOSEException e) {
            fail();
        }
    }

    @Test
    void validateForIdTokenHint_InvalidSigning_ES256() {
        try {
            JWK es256 =
                    new ECKeyGenerator(Curve.P_256)
                            .keyID("es")
                            .algorithm(new Algorithm("ES256"))
                            .generate();
            JWKSet jwks = new JWKSet(List.of(es256));
            var jws = new JWSIssuer(jwks).issue("es", null, Map.of());
            sut.validateForIdTokenHint(jws.serialize(), null);
            fail();
        } catch (InvalidIDTokenException e) {
            assertEquals("Failed to verify signature", e.getMessage());
        } catch (JOSEException e) {
            fail();
        }
    }

    @Test
    void validateForIdTokenHint_InvalidSigning_RS256() {
        try {
            JWK rs256 =
                    new RSAKeyGenerator(2048)
                            .keyID("rs")
                            .algorithm(new Algorithm("RS256"))
                            .generate();
            JWKSet jwks = new JWKSet(List.of(rs256));
            var jws = new JWSIssuer(jwks).issue("rs", null, Map.of());
            sut.validateForIdTokenHint(jws.serialize(), null);
            fail();
        } catch (InvalidIDTokenException e) {
            assertEquals("Failed to verify signature", e.getMessage());
        } catch (JOSEException e) {
            fail();
        }
    }

    @Test
    void validateForIdTokenHint_InvalidIss() {
        try {
            var jws = new JWSIssuer(jwks).issue("es", null, Map.of("iss", "invalid"));
            sut.validateForIdTokenHint(jws.serialize(), null);
            fail();
        } catch (InvalidIDTokenException e) {
            assertEquals("Issuer unmatched", e.getMessage());
        }
    }

    @Test
    void validateForIdTokenHint_InvalidAud() {
        try {
            var jws =
                    new JWSIssuer(jwks)
                            .issue("es", null, Map.of("iss", config.issuer, "aud", "invalid"));
            sut.validateForIdTokenHint(jws.serialize(), Fixtures.confidentialClient().build());
            fail();
        } catch (InvalidIDTokenException e) {
            assertEquals("Audience unmatched", e.getMessage());
        }
    }

    @Test
    void validateForIdTokenHint_InvalidAzp() {
        var client = Fixtures.confidentialClient().build();
        try {
            var jws =
                    new JWSIssuer(jwks)
                            .issue(
                                    "es",
                                    null,
                                    Map.of(
                                            "iss",
                                            config.issuer,
                                            "aud",
                                            client.clientId,
                                            "azp",
                                            "invalid"));
            sut.validateForIdTokenHint(jws.serialize(), client);
            fail();
        } catch (InvalidIDTokenException e) {
            assertEquals("Authorized Party unmatched", e.getMessage());
        }
    }

    @Test
    void validateForIdTokenHint_ClientNotSupportedAlg() {
        var client = Fixtures.confidentialClient().build();
        try {
            var jws =
                    new JWSIssuer(jwks)
                            .issue(
                                    "rs",
                                    null,
                                    Map.of(
                                            "iss",
                                            config.issuer,
                                            "aud",
                                            client.clientId,
                                            "azp",
                                            client.clientId));
            sut.validateForIdTokenHint(jws.serialize(), client);
            fail();
        } catch (InvalidIDTokenException e) {
            assertEquals("Client doesn't support RS256", e.getMessage());
        }
    }
}
