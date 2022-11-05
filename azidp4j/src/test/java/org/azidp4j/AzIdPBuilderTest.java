package org.azidp4j;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.Set;
import org.azidp4j.discovery.DiscoveryConfig;
import org.junit.jupiter.api.Test;

class AzIdPBuilderTest {

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
        } catch (AssertionError e) {
            // NOP
        }
    }
}
