package org.azidp4j;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.util.List;
import java.util.Set;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.SigningAlgorithm;
import org.azidp4j.discovery.DiscoveryConfig;
import org.junit.jupiter.api.Test;

class AzIdPBuilderTest {

    private AzIdPBuilder success() throws JOSEException {
        var rs256 =
                new RSAKeyGenerator(2048)
                        .keyID("RS256")
                        .algorithm(new Algorithm("RS256"))
                        .generate();
        var es256 =
                new ECKeyGenerator(Curve.P_256)
                        .keyID("ES256")
                        .algorithm(new Algorithm("ES256"))
                        .generate();
        var jwks = new JWKSet(List.of(rs256, es256));

        var discovery =
                DiscoveryConfig.builder()
                        .authorizationEndpoint("https://example.com/authorize")
                        .tokenEndpoint("https://example.com/token")
                        .userInfoEndpoint("https://example.com/userinfo")
                        .clientRegistrationEndpoint("https://example.com/client")
                        .jwksEndpoint("https://example.com/jwks")
                        .build();
        return AzIdP.initInMemory()
                .issuer("https://example.com")
                .jwkSet(jwks)
                .idTokenSigningAlgValuesSupported(
                        Set.of(SigningAlgorithm.RS256, SigningAlgorithm.ES256))
                .idTokenKidSupplier((alg -> alg.name()))
                .staticScopeAudienceMapper("audience")
                .scopesSupported(Set.of("openid"))
                .defaultScopes(Set.of())
                .discovery(discovery);
    }

    @Test
    void build_success() {
        var discovery =
                DiscoveryConfig.builder()
                        .authorizationEndpoint("https://example.com/authorize")
                        .tokenEndpoint("https://example.com/token")
                        .userInfoEndpoint("https://example.com/userinfo")
                        .clientRegistrationEndpoint("https://example.com/client")
                        .jwksEndpoint("https://example.com/jwks")
                        .build();
        AzIdP.initInMemory()
                .issuer("https://example.com")
                .jwkSet(new JWKSet())
                .idTokenKidSupplier((alg) -> "kid")
                .staticScopeAudienceMapper("audience")
                .scopesSupported(Set.of("openid"))
                .defaultScopes(Set.of())
                .discovery(discovery)
                .build();
    }

    @Test
    void build_error() {
        try {
            AzIdP.init().build();
            fail();
        } catch (IllegalArgumentException e) {
            System.out.println(e);
            // NOP
        }
    }

    @Test
    void build_error_issuerIsIllegalUri() throws JOSEException {
        try {
            success().issuer("illegal").build();
            fail();
        } catch (IllegalArgumentException e) {
            // NOP
        }
    }

    @Test
    void build_error_issuerIsNotHttps() throws JOSEException {
        try {
            success().issuer("http://example.com").build();
            fail();
        } catch (IllegalArgumentException e) {
            // NOP
        }
    }

    @Test
    void build_error_issuerHasQuery() throws JOSEException {
        try {
            success().issuer("https://example.com?a=b").build();
            fail();
        } catch (IllegalArgumentException e) {
            // NOP
        }
    }

    @Test
    void build_error_issuerHasFragment() throws JOSEException {
        try {
            success().issuer("http://example.com#a=b").build();
            fail();
        } catch (IllegalArgumentException e) {
            // NOP
        }
    }

    @Test
    void build_error_noKeyAgainstKid() {
        try {
            var rs256 =
                    new RSAKeyGenerator(2048)
                            .keyID("rs")
                            .algorithm(new Algorithm("RS256"))
                            .generate();
            var es256 =
                    new ECKeyGenerator(Curve.P_256)
                            .keyID("es")
                            .algorithm(new Algorithm("ES256"))
                            .generate();
            var jwks = new JWKSet(List.of(rs256, es256));
            success()
                    .jwkSet(jwks)
                    .idTokenKidSupplier((alg) -> "nothing")
                    .idTokenSigningAlgValuesSupported(Set.of(SigningAlgorithm.RS256))
                    .build();
            fail();
        } catch (IllegalArgumentException e) {
            // NOP
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void build_ResponseTypesSupportedHasNoneAndOther() {
        try {
            AzIdP.initInMemory()
                    .issuer("https://example.com")
                    .jwkSet(new JWKSet())
                    .idTokenKidSupplier((alg) -> "kid")
                    .staticScopeAudienceMapper("audience")
                    .scopesSupported(Set.of("openid"))
                    .defaultScopes(Set.of())
                    .responseTypesSupported(Set.of(Set.of(ResponseType.none, ResponseType.code)))
                    .build();
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "none response_type and others can't be combined");
        }
    }
}
