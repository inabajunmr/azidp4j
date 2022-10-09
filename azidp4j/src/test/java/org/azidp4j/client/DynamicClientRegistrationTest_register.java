package org.azidp4j.client;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.azidp4j.AccessTokenAssert;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.ResponseType;
import org.azidp4j.token.TokenEndpointAuthMethod;
import org.azidp4j.token.accesstoken.InMemoryAccessTokenStore;
import org.junit.jupiter.api.Test;

class DynamicClientRegistrationTest_register {

    @Test
    void success() throws JOSEException {
        // setup
        var rs256 = new RSAKeyGenerator(2048).keyID("abc").generate();
        var es256 = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(List.of(rs256, es256));
        var config = Fixtures.azIdPConfig(es256.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config, new InMemoryClientStore(), accessTokenStore, jwks);
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
                        .idTokenSignedResponseAlg("RS256")
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
        assertEquals(response.body.get("id_token_signed_response_alg"), "RS256");
        var at = response.body.get("registration_access_token");
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find((String) at).get(),
                (String) response.body.get("client_id"),
                config.issuer,
                (String) response.body.get("client_id"),
                "configure",
                Instant.now().getEpochSecond() + 3600);
    }

    @Test
    void success_Default() throws JOSEException, ParseException {
        // setup
        var rs256 = new RSAKeyGenerator(2048).keyID("abc").generate();
        var es256 = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(List.of(rs256, es256));
        var config = Fixtures.azIdPConfig(es256.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config, new InMemoryClientStore(), accessTokenStore, jwks);
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
        assertEquals(response.body.get("id_token_signed_response_alg"), "RS256");
        var at = response.body.get("registration_access_token");
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find((String) at).get(),
                (String) response.body.get("client_id"),
                config.issuer,
                (String) response.body.get("client_id"),
                "configure",
                Instant.now().getEpochSecond() + 3600);
    }
}
