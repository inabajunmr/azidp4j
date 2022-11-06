package org.azidp4j;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.Set;
import org.azidp4j.discovery.DiscoveryConfig;
import org.junit.jupiter.api.Test;

class AzIdPBuilderTest {

    private AzIdPBuilder success() {
        var discovery =
                DiscoveryConfig.builder()
                        .authorizationEndpoint("https://example.com/authorize")
                        .tokenEndpoint("https://example.com/token")
                        .userInfoEndpoint("https://example.com/userinfo")
                        .clientRegistrationEndpoint("https://example.com/client")
                        .clientConfigurationEndpointPattern(
                                "https://example.com/client/{CLIENT_ID}")
                        .jwksEndpoint("https://example.com/jwks")
                        .build();
        return AzIdP.initInMemory()
                .issuer("https://example.com")
                .jwkSet(new JWKSet())
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
                        .clientConfigurationEndpointPattern(
                                "https://example.com/client/{CLIENT_ID}")
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
    void build_error_issuerIsIllegalUri() {
        try {
            success().issuer("illegal").build();
            fail();
        } catch (IllegalArgumentException e) {
            // NOP
        }
    }

    @Test
    void build_error_issuerIsNotHttps() {
        try {
            success().issuer("http://example.com").build();
            fail();
        } catch (IllegalArgumentException e) {
            // NOP
        }
    }

    @Test
    void build_error_issuerHasQuery() {
        try {
            success().issuer("https://example.com?a=b").build();
            fail();
        } catch (IllegalArgumentException e) {
            // NOP
        }
    }

    @Test
    void build_error_issuerHasFragment() {
        try {
            success().issuer("http://example.com#a=b").build();
            fail();
        } catch (IllegalArgumentException e) {
            // NOP
        }
    }
}
