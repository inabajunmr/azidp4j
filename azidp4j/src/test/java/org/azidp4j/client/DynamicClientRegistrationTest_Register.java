package org.azidp4j.client;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.azidp4j.AccessTokenAssert;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.request.ResponseMode;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.request.ClientRequest;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.util.MapUtil;
import org.junit.jupiter.api.Test;

class DynamicClientRegistrationTest_Register {

    @Test
    void success_All_JwksUri() throws JOSEException {
        // setup
        var config = Fixtures.azIdPConfig();
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        null,
                        new InMemoryAccessTokenService(accessTokenStore),
                        (clientId) -> "http://localhost:8080/client/" + clientId);
        var req =
                new ClientRequest(
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
                                "default_acr_values",
                                List.of("acr1", "acr2"),
                                "initiate_login_uri",
                                "https://example.com"));

        // exercise
        var response = registration.register(req);

        // verify
        assertEquals(201, response.status);
        assertClientAll(response.body);
        assertEquals(response.body.get("jwks_uri"), "http://client.example.com/jwks");
        assertEquals(
                response.body.get("registration_client_uri"),
                "http://localhost:8080/client/" + response.body.get("client_id"));
        var at = response.body.get("registration_access_token");
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find((String) at).get(),
                (String) response.body.get("client_id"),
                config.issuer,
                (String) response.body.get("client_id"),
                "configure",
                Instant.now().getEpochSecond() + 3600);

        // read
        var read = registration.read((String) response.body.get("client_id"));
        assertEquals(read.status, 200);
        assertClientAll(read.body);
        assertEquals(read.body.get("jwks_uri"), "http://client.example.com/jwks");
    }

    @Test
    void success_All_Jwks() throws JOSEException {
        // setup
        var config = Fixtures.azIdPConfig();
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        null,
                        new InMemoryAccessTokenService(accessTokenStore),
                        (clientId) -> "http://localhost:8080/client/" + clientId);
        var req =
                new ClientRequest(
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
                                "jwks",
                                Fixtures.jwkSet().toJSONObject(),
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

        // exercise
        var response = registration.register(req);

        // verify
        assertEquals(201, response.status);
        assertClientAll(response.body);
        assertEquals(response.body.get("jwks"), Fixtures.jwkSet().toJSONObject());
        assertEquals(
                response.body.get("registration_client_uri"),
                "http://localhost:8080/client/" + response.body.get("client_id"));
        var at = response.body.get("registration_access_token");
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find((String) at).get(),
                (String) response.body.get("client_id"),
                config.issuer,
                (String) response.body.get("client_id"),
                "configure",
                Instant.now().getEpochSecond() + 3600);

        // read
        var read = registration.read((String) response.body.get("client_id"));
        assertEquals(read.status, 200);
        assertClientAll(read.body);
        assertEquals(read.body.get("jwks"), Fixtures.jwkSet().toJSONObject());
    }

    void assertClientAll(Map<String, Object> responseBody) {
        assertEquals(
                responseBody.get("redirect_uris"),
                Set.of(
                        "https://client.example.com/callback1",
                        "https://client.example.com/callback2"));
        assertEquals(
                responseBody.get("grant_types"),
                Set.of("authorization_code", "implicit", "refresh_token", "client_credentials"));
        assertEquals(responseBody.get("application_type"), "web");
        assertEquals(responseBody.get("response_types"), Set.of("code", "token", "id_token"));
        assertEquals(responseBody.get("client_name"), "client");
        assertEquals(responseBody.get("client_name#ja"), "クライアント");
        assertEquals(responseBody.get("client_uri"), "http://client.example.com");
        assertEquals(responseBody.get("logo_uri"), "http://client.example.com/logo");
        assertEquals(responseBody.get("scope"), "rs:scope1 rs:scope2");
        assertEquals(responseBody.get("contacts"), List.of("hello", "world"));
        assertEquals(responseBody.get("tos_uri"), "http://client.example.com/tos");
        assertEquals(responseBody.get("tos_uri#ja"), "http://client.example.com/tos/ja");
        assertEquals(responseBody.get("policy_uri"), "http://client.example.com/policy");
        assertEquals(responseBody.get("policy_uri#ja"), "http://client.example.com/policy/ja");
        assertEquals(responseBody.get("software_id"), "azidp");
        assertEquals(responseBody.get("software_version"), "1.0.0");
        assertEquals(responseBody.get("token_endpoint_auth_method"), "client_secret_basic");
        assertEquals(responseBody.get("token_endpoint_auth_signing_alg"), "RS256");
        assertEquals(responseBody.get("id_token_signed_response_alg"), "RS256");
        assertEquals(responseBody.get("default_max_age"), 100L);
        assertEquals(responseBody.get("require_auth_time"), true);
        assertEquals(responseBody.get("initiate_login_uri"), "https://example.com");
    }

    @Test
    void success_Default() throws JOSEException {
        // setup
        var config = Fixtures.azIdPConfig();
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        null,
                        new InMemoryAccessTokenService(accessTokenStore),
                        (clientId) -> "http://localhost:8080/client/" + clientId);

        // exercise
        var response = registration.register(new ClientRequest(Map.of()));

        // verify
        assertEquals(201, response.status);
        assertEquals(response.body.get("redirect_uris"), Set.of());
        assertEquals(response.body.get("grant_types"), Set.of(GrantType.authorization_code.name()));
        assertEquals(response.body.get("application_type"), "web");
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

    @Test
    void failure_UnsupportedTokenEndpointAuthMethod() {
        // setup
        var config = Fixtures.azIdPConfig();
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        null,
                        new InMemoryAccessTokenService(accessTokenStore),
                        (clientId) -> "http://localhost:8080/client/" + clientId);

        var response =
                registration.register(
                        new ClientRequest(
                                Map.of("token_endpoint_auth_method", "client_secret_post")));
        assertEquals(400, response.status);
        assertEquals("invalid_client_metadata", response.body.get("error"));
    }

    @Test
    void failure_UnsupportedTokenEndpointAuthSigningAlg() {
        // setup
        var config =
                new AzIdPConfig(
                        "http://localhost:8080",
                        Set.of("openid", "rs:scope1", "rs:scope2", "rs:scope3", "default"),
                        Set.of("openid", "rs:scope1"),
                        Set.of(TokenEndpointAuthMethod.client_secret_jwt),
                        Set.of(SigningAlgorithm.ES256),
                        Set.of(TokenEndpointAuthMethod.client_secret_basic),
                        null,
                        Set.of(TokenEndpointAuthMethod.client_secret_basic),
                        null,
                        Set.of(GrantType.authorization_code),
                        Set.of(Set.of(ResponseType.code)),
                        Set.of(ResponseMode.query, ResponseMode.fragment),
                        Set.of(
                                SigningAlgorithm.ES256,
                                SigningAlgorithm.RS256,
                                SigningAlgorithm.none),
                        List.of("acr"),
                        Duration.ofSeconds(3600),
                        Duration.ofSeconds(600),
                        Duration.ofSeconds(604800),
                        Duration.ofSeconds(3600));

        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        null,
                        new InMemoryAccessTokenService(accessTokenStore),
                        (clientId) -> "http://localhost:8080/client/" + clientId);

        var response =
                registration.register(
                        new ClientRequest(
                                Map.of(
                                        "token_endpoint_auth_method",
                                        "client_secret_jwt",
                                        "token_endpoint_auth_signing_alg",
                                        "RS256")));
        assertEquals(400, response.status);
        assertEquals("invalid_client_metadata", response.body.get("error"));
    }

    @Test
    void failure_RequiredTokenEndpointAuthSigningAlg() {
        // setup
        var config =
                new AzIdPConfig(
                        "http://localhost:8080",
                        Set.of("openid", "rs:scope1", "rs:scope2", "rs:scope3", "default"),
                        Set.of("openid", "rs:scope1"),
                        Set.of(TokenEndpointAuthMethod.client_secret_jwt),
                        Set.of(SigningAlgorithm.ES256),
                        Set.of(TokenEndpointAuthMethod.client_secret_basic),
                        null,
                        Set.of(TokenEndpointAuthMethod.client_secret_basic),
                        null,
                        Set.of(GrantType.authorization_code),
                        Set.of(Set.of(ResponseType.code)),
                        Set.of(ResponseMode.query, ResponseMode.fragment),
                        Set.of(
                                SigningAlgorithm.ES256,
                                SigningAlgorithm.RS256,
                                SigningAlgorithm.none),
                        List.of("acr"),
                        Duration.ofSeconds(3600),
                        Duration.ofSeconds(600),
                        Duration.ofSeconds(604800),
                        Duration.ofSeconds(3600));

        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        null,
                        new InMemoryAccessTokenService(accessTokenStore),
                        (clientId) -> "http://localhost:8080/client/" + clientId);

        // client_secret_jwt but not signing alg
        var response =
                registration.register(
                        new ClientRequest(
                                Map.of("token_endpoint_auth_method", "client_secret_jwt")));
        assertEquals(400, response.status);
        assertEquals("invalid_client_metadata", response.body.get("error"));
    }

    @Test
    void failure_IllegalGrantType() {
        // setup
        var config = Fixtures.azIdPConfig();
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        null,
                        new InMemoryAccessTokenService(accessTokenStore),
                        (clientId) -> "http://localhost:8080/client/" + clientId);

        // exercise
        var response =
                registration.register(
                        new ClientRequest(
                                Map.of(
                                        "grant_types",
                                        Set.of("authorization_code", "implicit", "illegal"))));

        // verify
        assertEquals(400, response.status);
        assertEquals("invalid_client_metadata", response.body.get("error"));
    }

    @Test
    void failure_IllegalResponseType() {
        // setup
        var config = Fixtures.azIdPConfig();
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        null,
                        new InMemoryAccessTokenService(accessTokenStore),
                        (clientId) -> "http://localhost:8080/client/" + clientId);

        // exercise
        var response =
                registration.register(
                        new ClientRequest(
                                Map.of("response_types", Set.of("code", "token", "illegal"))));

        // verify
        assertEquals(400, response.status);
        assertEquals("invalid_client_metadata", response.body.get("error"));
    }

    @Test
    void failure_IllegalApplicationType() {
        // setup
        var config = Fixtures.azIdPConfig();
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        null,
                        new InMemoryAccessTokenService(accessTokenStore),
                        (clientId) -> "http://localhost:8080/client/" + clientId);

        // exercise
        var response =
                registration.register(new ClientRequest(Map.of("application_type", "illegal")));

        // verify
        assertEquals(400, response.status);
        assertEquals("invalid_client_metadata", response.body.get("error"));
    }

    @Test
    void failure_TokenEndpointAuthMethod() {
        // setup
        var config = Fixtures.azIdPConfig();
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        null,
                        new InMemoryAccessTokenService(accessTokenStore),
                        (clientId) -> "http://localhost:8080/client/" + clientId);

        // exercise
        var response =
                registration.register(
                        new ClientRequest(Map.of("token_endpoint_auth_method", "illegal")));

        // verify
        assertEquals(400, response.status);
        assertEquals("invalid_client_metadata", response.body.get("error"));
    }

    @Test
    void failure_IllegalIdTokenSignedResponseAlg() {
        // setup
        var config = Fixtures.azIdPConfig();
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        null,
                        new InMemoryAccessTokenService(accessTokenStore),
                        (clientId) -> "http://localhost:8080/client/" + clientId);

        // exercise
        var response =
                registration.register(
                        new ClientRequest(Map.of("id_token_signed_response_alg", "illegal")));

        // verify
        assertEquals(400, response.status);
        assertEquals("invalid_client_metadata", response.body.get("error"));
    }

    @Test
    void failure_CustomizableClientValidatorError() {
        // setup
        var config = Fixtures.azIdPConfig();
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        client -> {
                            throw new IllegalArgumentException();
                        },
                        new InMemoryAccessTokenService(accessTokenStore),
                        (clientId) -> "http://localhost:8080/client/" + clientId);

        // exercise
        var response = registration.register(new ClientRequest(Map.of()));

        // verify
        assertEquals(400, response.status);
        assertEquals("invalid_client_metadata", response.body.get("error"));
    }
}
