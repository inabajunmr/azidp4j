package org.azidp4j.client;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.azidp4j.Fixtures;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.accesstoken.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.InMemoryAccessTokenStore;
import org.junit.jupiter.api.Test;

class DynamicClientRegistrationTest_configure {

    @Test
    void success() throws JOSEException {
        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        new InMemoryAccessTokenService(
                                config,
                                new SampleScopeAudienceMapper(),
                                new InMemoryAccessTokenStore()));
        var registrationResponse =
                registration.register(ClientRegistrationRequest.builder().build());
        var configurationRequest =
                ClientConfigurationRequest.builder()
                        .clientId((String) registrationResponse.body.get("client_id"))
                        .scope("openid")
                        .build();

        // exercise
        var response = registration.configure(configurationRequest);

        // verify
        assertEquals(200, response.status);
        assertEquals(response.body.get("scope"), "openid");
    }
}
