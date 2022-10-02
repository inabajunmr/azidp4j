package org.azidp4j.client;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Set;
import org.azidp4j.authorize.ResponseType;
import org.azidp4j.token.TokenEndpointAuthMethod;
import org.junit.jupiter.api.Test;

class DynamicClientRegistrationTest {

    @Test
    void success() {
        // setup
        var registration = new DynamicClientRegistration(new InMemoryClientStore());
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
    }

    @Test
    void success_Default() {
        // setup
        var registration = new DynamicClientRegistration(new InMemoryClientStore());
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
    }
    // TODO defaults
}
