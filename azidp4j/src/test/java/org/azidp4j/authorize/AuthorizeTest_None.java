package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.client.Client;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.TokenEndpointAuthMethod;
import org.azidp4j.token.accesstoken.AccessTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.junit.jupiter.api.Test;

class AuthorizeTest_None {

    @Test
    void none() throws JOSEException {
        // setup
        var clientStore = new InMemoryClientStore();
        var client =
                new Client(
                        "client1",
                        "clientSecret",
                        Set.of("http://rp1.example.com", "http://rp2.example.com"),
                        Set.of(),
                        Set.of(ResponseType.none),
                        "rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic);
        clientStore.save(client);
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var config =
                new AzIdPConfig(
                        "az.example.com", key.getKeyID(), key.getKeyID(), 3600, 604800, 3600);
        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeStore(),
                        new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper()),
                        new IDTokenIssuer(config, new JWKSet()),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("none")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserId("username")
                        .state("xyz")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.status, 302);
        var location = response.headers().get("Location");
        var queryMap =
                Arrays.stream(URI.create(location).getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertNotNull(queryMap.get("state"));
        assertNull(queryMap.get("access_token"));
        assertNull(queryMap.get("code"));
        assertNull(queryMap.get("id_token"));
    }
}
