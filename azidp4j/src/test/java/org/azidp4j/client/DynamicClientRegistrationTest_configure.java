package org.azidp4j.client;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.azidp4j.Fixtures;
import org.azidp4j.client.request.ClientRequest;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.util.MapUtil;
import org.junit.jupiter.api.Test;

class DynamicClientRegistrationTest_configure {

    @Test
    void success_All() throws JOSEException {
        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        null,
                        new InMemoryAccessTokenService(new InMemoryAccessTokenStore()));
        var registrationResponse = registration.register(registerAll());
        var configurationRequest =
                new ClientRequest(
                        MapUtil.ofNullable(
                                "redirect_uris",
                                        Set.of(
                                                "app://client.example.com/callback1/new",
                                                "app://client.example.com/callback2/new"),
                                "application_type", "native",
                                "grant_types",
                                        Set.of(
                                                "authorization_code",
                                                "implicit",
                                                "password", // add
                                                "refresh_token",
                                                "client_credentials"),
                                "response_types", Set.of("code", "token", "id_token", "none"),
                                "client_name", "client/new",
                                "client_name#ja", "クライアント/new",
                                "client_name#cn", "客户/new",
                                "client_uri", "http://client.example.com/new",
                                "logo_uri", "http://client.example.com/logo/new",
                                "scope", "rs:scope1 rs:scope2 rs:scope3",
                                "contacts", List.of("hello", "world", "new"),
                                "tos_uri", "http://client.example.com/tos/new",
                                "tos_uri#ja", "http://client.example.com/tos/ja/new",
                                "tos_uri#cn", "http://client.example.com/tos/cn/new",
                                "policy_uri", "http://client.example.com/policy/new",
                                "policy_uri#ja", "http://client.example.com/policy/ja/new",
                                "policy_uri#cn", "http://client.example.com/policy/cn/new",
                                "jwks_uri", "http://client.example.com/jwks/new",
                                "software_id", "azidp/new",
                                "software_version", "1.0.1",
                                "token_endpoint_auth_method", "client_secret_post",
                                "token_endpoint_auth_signing_alg", "ES256",
                                "id_token_signed_response_alg", "ES256",
                                "default_max_age", 50L,
                                "require_auth_time", false,
                                "initiate_login_uri", "https://example.com/new"));

        // exercise
        var response =
                registration.configure(
                        registrationResponse.body.get("client_id").toString(),
                        configurationRequest);

        // verify
        assertEquals(200, response.status);
        assertEquals(response.body.get("client_id"), registrationResponse.body.get("client_id"));
        assertEquals(
                response.body.get("redirect_uris"),
                Set.of(
                        "app://client.example.com/callback1/new",
                        "app://client.example.com/callback2/new"));
        assertEquals(
                response.body.get("grant_types"),
                Set.of(
                        "authorization_code",
                        "implicit",
                        "refresh_token",
                        "client_credentials",
                        "password"));
        assertEquals(response.body.get("application_type"), "native");
        assertEquals(
                response.body.get("response_types"), Set.of("code", "token", "id_token", "none"));
        assertEquals(response.body.get("client_name"), "client/new");
        assertEquals(response.body.get("client_name#ja"), "クライアント/new");
        assertEquals(response.body.get("client_name#cn"), "客户/new");
        assertEquals(response.body.get("client_uri"), "http://client.example.com/new");
        assertEquals(response.body.get("logo_uri"), "http://client.example.com/logo/new");
        assertEquals(response.body.get("scope"), "rs:scope1 rs:scope2 rs:scope3");
        assertEquals(response.body.get("contacts"), List.of("hello", "world", "new"));
        assertEquals(response.body.get("tos_uri"), "http://client.example.com/tos/new");
        assertEquals(response.body.get("tos_uri#ja"), "http://client.example.com/tos/ja/new");
        assertEquals(response.body.get("tos_uri#cn"), "http://client.example.com/tos/cn/new");
        assertEquals(response.body.get("policy_uri"), "http://client.example.com/policy/new");
        assertEquals(response.body.get("policy_uri#ja"), "http://client.example.com/policy/ja/new");
        assertEquals(response.body.get("policy_uri#cn"), "http://client.example.com/policy/cn/new");
        assertEquals(response.body.get("jwks_uri"), "http://client.example.com/jwks/new");
        assertEquals(response.body.get("software_id"), "azidp/new");
        assertEquals(response.body.get("software_version"), "1.0.1");
        assertEquals(response.body.get("token_endpoint_auth_method"), "client_secret_post");
        assertEquals(response.body.get("token_endpoint_auth_signing_alg"), "ES256");
        assertEquals(response.body.get("default_max_age"), 50L);
        assertEquals(response.body.get("require_auth_time"), false);
        assertEquals(response.body.get("initiate_login_uri"), "https://example.com/new");
    }

    @Test
    void success_None() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        null,
                        new InMemoryAccessTokenService(new InMemoryAccessTokenStore()));
        var registrationResponse = registration.register(registerAll());
        var configurationRequest = new ClientRequest(Map.of());

        // exercise
        var response =
                registration.configure(
                        registrationResponse.body.get("client_id").toString(),
                        configurationRequest);

        // verify
        assertEquals(response.status, 200);
        assertEquals(response.body.get("client_id"), registrationResponse.body.get("client_id"));
        assertEquals(
                response.body.get("redirect_uris"),
                Set.of(
                        "https://client.example.com/callback1",
                        "https://client.example.com/callback2"));
        assertEquals(
                response.body.get("grant_types"),
                Set.of("authorization_code", "implicit", "refresh_token", "client_credentials"));
        assertEquals(response.body.get("application_type"), "web");
        assertEquals(response.body.get("response_types"), Set.of("code", "token", "id_token"));
        assertEquals(response.body.get("client_name"), "client");
        assertEquals(response.body.get("client_name#ja"), "クライアント");
        assertEquals(response.body.get("client_uri"), "http://client.example.com");
        assertEquals(response.body.get("logo_uri"), "http://client.example.com/logo");
        assertEquals(response.body.get("scope"), "rs:scope1 rs:scope2");
        assertEquals(response.body.get("contacts"), List.of("hello", "world"));
        assertEquals(response.body.get("tos_uri"), "http://client.example.com/tos");
        assertEquals(response.body.get("tos_uri#ja"), "http://client.example.com/tos/ja");
        assertEquals(response.body.get("policy_uri"), "http://client.example.com/policy");
        assertEquals(response.body.get("policy_uri#ja"), "http://client.example.com/policy/ja");
        assertEquals(response.body.get("jwks_uri"), "http://client.example.com/jwks");
        assertEquals(response.body.get("software_id"), "azidp");
        assertEquals(response.body.get("software_version"), "1.0.0");
        assertEquals(response.body.get("token_endpoint_auth_method"), "client_secret_basic");
        assertEquals(response.body.get("token_endpoint_auth_signing_alg"), "RS256");
        assertEquals(response.body.get("id_token_signed_response_alg"), "RS256");
        assertEquals(response.body.get("default_max_age"), 100L);
        assertEquals(response.body.get("require_auth_time"), true);
        assertEquals(response.body.get("initiate_login_uri"), "https://example.com");
    }

    @Test
    void validationError_JwksAndJwksUri() throws JOSEException {
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        null,
                        new InMemoryAccessTokenService(new InMemoryAccessTokenStore()));
        var registrationResponse = registration.register(registerAll());

        // exercise
        var response =
                registration.configure(
                        registrationResponse.body.get("client_id").toString(),
                        new ClientRequest(Map.of("jwks", "jwks")));

        // verify
        assertEquals(response.status, 400);
    }

    @Test
    void validationError_publicClientAndClientCredentials() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        null,
                        new InMemoryAccessTokenService(new InMemoryAccessTokenStore()));
        var registrationResponse = registration.register(registerAll());

        // exercise
        var response =
                registration.configure(
                        registrationResponse.body.get("client_id").toString(),
                        new ClientRequest(
                                Map.of(
                                        "grant_types",
                                        Set.of("client_credentials"),
                                        "token_endpoint_auth_method",
                                        "none")));

        // verify
        assertEquals(response.status, 400);
    }

    private ClientRequest registerAll() {
        return new ClientRequest(
                MapUtil.ofNullable(
                        "redirect_uris",
                        Set.of(
                                "https://client.example.com/callback1",
                                "https://client.example.com/callback2"),
                        "grant_types",
                        Set.of(
                                "authorization_code",
                                "implicit",
                                "refresh_token",
                                "client_credentials"),
                        "application_type",
                        "web",
                        "response_types",
                        Set.of("code", "token", "id_token"),
                        "client_name",
                        "client",
                        "client_name#ja",
                        "クライアント",
                        "client_uri",
                        "http://client.example.com",
                        "logo_uri",
                        "http://client.example.com/logo",
                        "scope",
                        "rs:scope1 rs:scope2",
                        "contacts",
                        List.of("hello", "world"),
                        "tos_uri",
                        "http://client.example.com/tos",
                        "tos_uri#ja",
                        "http://client.example.com/tos/ja",
                        "policy_uri",
                        "http://client.example.com/policy",
                        "policy_uri#ja",
                        "http://client.example.com/policy/ja",
                        "jwks_uri",
                        "http://client.example.com/jwks",
                        "software_id",
                        "azidp",
                        "software_version",
                        "1.0.0",
                        "token_endpoint_auth_method",
                        "client_secret_basic",
                        "token_endpoint_auth_signing_alg",
                        "RS256",
                        "id_token_signed_response_alg",
                        "RS256",
                        "default_max_age",
                        100L,
                        "require_auth_time",
                        true,
                        "initiate_login_uri",
                        "https://example.com"));
    }
}
