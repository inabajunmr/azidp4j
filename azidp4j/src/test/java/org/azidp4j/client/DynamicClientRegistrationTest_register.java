package org.azidp4j.client;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.text.ParseException;
import java.time.Instant;
import java.util.Set;
import org.azidp4j.AccessTokenAssert;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.ResponseType;
import org.azidp4j.token.TokenEndpointAuthMethod;
import org.azidp4j.token.accesstoken.AccessTokenIssuer;
import org.junit.jupiter.api.Test;

class DynamicClientRegistrationTest_register {

    @Test
    void success() throws JOSEException, ParseException {
        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var atIssuer = new AccessTokenIssuer(config, jwks, scope -> Set.of("rs"));
        var registration =
                new DynamicClientRegistration(config, new InMemoryClientStore(), atIssuer);
        var req =
                ClientRegistrationRequest.builder()
                        .redirectUris(
                                Set.of(
                                        "http://client.example.com/callback1",
                                        "http://client.example.com/callback2"))
                        .grantTypes(
                                Set.of(
                                        "authorization_code",
                                        "implicit",
                                        "refresh_token",
                                        "client_credentials"))
                        .scope("scope1 scope2")
                        .responseTypes(Set.of("code", "token", "id_token"))
                        .tokenEndpointAuthMethod("client_secret_basic")
                        .build();

        // exercise
        var response = registration.register(req);

        // verify
        assertEquals(201, response.status);
        assertEquals(
                response.body.get("redirect_uris"),
                Set.of(
                        "http://client.example.com/callback1",
                        "http://client.example.com/callback2"));
        assertEquals(
                response.body.get("grant_types"),
                Set.of("authorization_code", "implicit", "refresh_token", "client_credentials"));
        assertEquals(response.body.get("response_types"), Set.of("code", "token", "id_token"));
        assertEquals(response.body.get("scope"), "scope1 scope2");
        assertEquals(response.body.get("token_endpoint_auth_method"), "client_secret_basic");
        assertEquals(
                response.body.get("registration_client_uri"),
                "http://localhost:8080/client/" + response.body.get("client_id"));
        var at = response.body.get("registration_access_token");
        AccessTokenAssert.assertAccessToken(
                (String) at,
                key,
                (String) response.body.get("client_id"),
                config.issuer,
                (String) response.body.get("client_id"),
                "configure",
                config.issuer,
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond());
    }

    @Test
    void success_Default() throws JOSEException, ParseException {
        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var atIssuer = new AccessTokenIssuer(config, jwks, scope -> Set.of("rs"));
        var registration =
                new DynamicClientRegistration(config, new InMemoryClientStore(), atIssuer);
        var req = ClientRegistrationRequest.builder().build();

        // exercise
        var response = registration.register(req);

        // verify
        assertEquals(201, response.status);
        assertEquals(response.body.get("redirect_uris"), Set.of());
        assertEquals(response.body.get("grant_types"), Set.of(GrantType.authorization_code.name()));
        assertEquals(response.body.get("response_types"), Set.of(ResponseType.code.name()));
        assertNull(response.body.get("scope"));
        assertEquals(
                response.body.get("token_endpoint_auth_method"),
                TokenEndpointAuthMethod.client_secret_basic.name());
        assertEquals(
                response.body.get("registration_client_uri"),
                "http://localhost:8080/client/" + response.body.get("client_id"));
        var at = response.body.get("registration_access_token");
        AccessTokenAssert.assertAccessToken(
                (String) at,
                key,
                (String) response.body.get("client_id"),
                config.issuer,
                (String) response.body.get("client_id"),
                "configure",
                config.issuer,
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond());
    }
}
