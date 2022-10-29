package org.azidp4j.client;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.azidp4j.AccessTokenAssert;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.request.ClientRegistrationRequest;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.util.HumanReadable;
import org.junit.jupiter.api.Test;

class DynamicClientRegistrationTest_register {

    @Test
    void success_All_Jwks() throws JOSEException {
        // setup
        var es256 = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var config = Fixtures.azIdPConfig(es256.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        new InMemoryAccessTokenService(accessTokenStore));
        var req =
                ClientRegistrationRequest.builder()
                        .redirectUris(
                                Set.of(
                                        "https://client.example.com/callback1",
                                        "https://client.example.com/callback2"))
                        .grantTypes(
                                Set.of(
                                        "authorization_code",
                                        "implicit",
                                        "refresh_token",
                                        "client_credentials"))
                        .applicationType("web")
                        .responseTypes(Set.of("code", "token", "id_token"))
                        .clientName(
                                new HumanReadable<>(
                                        "client_name", "client", Map.of("ja", "クライアント")))
                        .clientUri("http://client.example.com")
                        .logoUri("http://client.example.com/logo")
                        .scope("scope1 scope2")
                        .contacts(List.of("hello", "world"))
                        .tosUri(
                                new HumanReadable<>(
                                        "tos_uri",
                                        "http://client.example.com/tos",
                                        Map.of("ja", "http://client.example.com/tos/ja")))
                        .policyUri(
                                new HumanReadable<>(
                                        "policy_uri",
                                        "http://client.example.com/policy",
                                        Map.of("ja", "http://client.example.com/policy/ja")))
                        .jwksUri("http://client.example.com/jwks")
                        .softwareId("azidp")
                        .softwareVersion("1.0.0")
                        .tokenEndpointAuthMethod("client_secret_basic")
                        .tokenEndpointAuthSigningAlg("RS256")
                        .idTokenSignedResponseAlg("RS256")
                        .defaultMaxAge(100L)
                        .requireAuthTime(true)
                        .initiateLoginUri("https://example.com")
                        .build();

        // exercise
        var response = registration.register(req);

        // verify
        assertEquals(201, response.status);
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
        assertEquals(
                response.body.get("client_name"),
                Map.of("client_name", "client", "client_name#ja", "クライアント"));
        assertEquals(response.body.get("client_uri"), "http://client.example.com");
        assertEquals(response.body.get("logo_uri"), "http://client.example.com/logo");
        assertEquals(response.body.get("scope"), "scope1 scope2");
        assertEquals(response.body.get("contacts"), List.of("hello", "world"));
        assertEquals(
                response.body.get("tos_uri"),
                Map.of(
                        "tos_uri",
                        "http://client.example.com/tos",
                        "tos_uri#ja",
                        "http://client.example.com/tos/ja"));
        assertEquals(
                response.body.get("policy_uri"),
                Map.of(
                        "policy_uri",
                        "http://client.example.com/policy",
                        "policy_uri#ja",
                        "http://client.example.com/policy/ja"));
        assertEquals(response.body.get("jwks_uri"), "http://client.example.com/jwks");
        assertEquals(response.body.get("software_id"), "azidp");
        assertEquals(response.body.get("software_version"), "1.0.0");
        assertEquals(response.body.get("token_endpoint_auth_method"), "client_secret_basic");
        assertEquals(
                response.body.get("registration_client_uri"),
                "http://localhost:8080/client/" + response.body.get("client_id"));
        assertEquals(response.body.get("token_endpoint_auth_signing_alg"), "RS256");
        assertEquals(response.body.get("id_token_signed_response_alg"), "RS256");
        assertEquals(response.body.get("default_max_age"), 100L);
        assertEquals(response.body.get("require_auth_time"), true);
        assertEquals(response.body.get("initiate_login_uri"), "https://example.com");
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
    void success_All_JwksUri() throws JOSEException {
        // setup
        var es256 = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var config = Fixtures.azIdPConfig(es256.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        new InMemoryAccessTokenService(accessTokenStore));
        var req =
                ClientRegistrationRequest.builder()
                        .redirectUris(
                                Set.of(
                                        "https://client.example.com/callback1",
                                        "https://client.example.com/callback2"))
                        .grantTypes(
                                Set.of(
                                        "authorization_code",
                                        "implicit",
                                        "refresh_token",
                                        "client_credentials"))
                        .applicationType("web")
                        .responseTypes(Set.of("code", "token", "id_token"))
                        .clientName(
                                new HumanReadable<>(
                                        "client_name", "client", Map.of("ja", "クライアント")))
                        .clientUri("http://client.example.com")
                        .logoUri("http://client.example.com/logo")
                        .scope("scope1 scope2")
                        .contacts(List.of("hello", "world"))
                        .tosUri(
                                new HumanReadable<>(
                                        "tos_uri",
                                        "http://client.example.com/tos",
                                        Map.of("ja", "http://client.example.com/tos/ja")))
                        .policyUri(
                                new HumanReadable<>(
                                        "policy_uri",
                                        "http://client.example.com/policy",
                                        Map.of("ja", "http://client.example.com/policy/ja")))
                        .jwks("jwks")
                        .softwareId("azidp")
                        .softwareVersion("1.0.0")
                        .tokenEndpointAuthMethod("client_secret_basic")
                        .tokenEndpointAuthSigningAlg("RS256")
                        .idTokenSignedResponseAlg("RS256")
                        .defaultMaxAge(100L)
                        .requireAuthTime(true)
                        .initiateLoginUri("https://example.com")
                        .build();

        // exercise
        var response = registration.register(req);

        // verify
        assertEquals(201, response.status);
        assertEquals(
                response.body.get("redirect_uris"),
                Set.of(
                        "https://client.example.com/callback1",
                        "https://client.example.com/callback2"));
        assertEquals(
                response.body.get("grant_types"),
                Set.of("authorization_code", "implicit", "refresh_token", "client_credentials"));
        assertEquals(response.body.get("response_types"), Set.of("code", "token", "id_token"));
        assertEquals(
                response.body.get("client_name"),
                Map.of("client_name", "client", "client_name#ja", "クライアント"));
        assertEquals(response.body.get("client_uri"), "http://client.example.com");
        assertEquals(response.body.get("logo_uri"), "http://client.example.com/logo");
        assertEquals(response.body.get("scope"), "scope1 scope2");
        assertEquals(response.body.get("contacts"), List.of("hello", "world"));
        assertEquals(
                response.body.get("tos_uri"),
                Map.of(
                        "tos_uri",
                        "http://client.example.com/tos",
                        "tos_uri#ja",
                        "http://client.example.com/tos/ja"));
        assertEquals(
                response.body.get("policy_uri"),
                Map.of(
                        "policy_uri",
                        "http://client.example.com/policy",
                        "policy_uri#ja",
                        "http://client.example.com/policy/ja"));
        assertEquals(response.body.get("jwks"), "jwks");
        assertEquals(response.body.get("software_id"), "azidp");
        assertEquals(response.body.get("software_version"), "1.0.0");
        assertEquals(response.body.get("token_endpoint_auth_method"), "client_secret_basic");
        assertEquals(
                response.body.get("registration_client_uri"),
                "http://localhost:8080/client/" + response.body.get("client_id"));
        assertEquals(response.body.get("token_endpoint_auth_signing_alg"), "RS256");
        assertEquals(response.body.get("id_token_signed_response_alg"), "RS256");
        assertEquals(response.body.get("default_max_age"), 100L);
        assertEquals(response.body.get("require_auth_time"), true);
        assertEquals(response.body.get("initiate_login_uri"), "https://example.com");
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
    void success_Default() throws JOSEException {
        // setup
        var es256 = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var config = Fixtures.azIdPConfig(es256.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        new InMemoryAccessTokenService(accessTokenStore));
        var req = ClientRegistrationRequest.builder().build();

        // exercise
        var response = registration.register(req);

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

    // TODO after extracting class for client validator, following tests should be at client
    // validator test

    @Test
    void validationError_BothJwksAndJwksUri() throws JOSEException {
        // setup
        var rs256 = new RSAKeyGenerator(2048).keyID("abc").generate();
        var es256 = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var config = Fixtures.azIdPConfig(es256.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        new InMemoryAccessTokenService(accessTokenStore));
        var req =
                ClientRegistrationRequest.builder()
                        .jwks("jwks")
                        .jwksUri("http://client.example.com/jwks")
                        .build();

        // exercise
        var response = registration.register(req);

        // verify
        assertEquals(400, response.status);
    }

    @Test
    void validationError_publicClientAndClientCredentials() throws JOSEException {

        // setup
        var es256 = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var config = Fixtures.azIdPConfig(es256.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        new InMemoryAccessTokenService(accessTokenStore));
        var req =
                ClientRegistrationRequest.builder()
                        .grantTypes(Set.of("client_credentials"))
                        .tokenEndpointAuthMethod("none")
                        .build();

        // exercise
        var response = registration.register(req);

        // verify
        assertEquals(400, response.status);
    }

    @Test
    void validationError_applicationTypeIsWebAndImplicitIllegalRedirectUriHttp()
            throws JOSEException {

        // setup
        var es256 = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var config = Fixtures.azIdPConfig(es256.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        new InMemoryAccessTokenService(accessTokenStore));
        var req =
                ClientRegistrationRequest.builder()
                        .applicationType("web")
                        .grantTypes(Set.of("implicit"))
                        .redirectUris(Set.of("http://example.com"))
                        .build();

        // exercise
        var response = registration.register(req);

        // verify
        assertEquals(400, response.status);
    }

    @Test
    void validationError_applicationTypeIsWebAndImplicitIllegalRedirectUriLocalhost()
            throws JOSEException {

        // setup
        var es256 = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var config = Fixtures.azIdPConfig(es256.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        new InMemoryAccessTokenService(accessTokenStore));
        var req =
                ClientRegistrationRequest.builder()
                        .applicationType("web")
                        .grantTypes(Set.of("implicit"))
                        .redirectUris(Set.of("https://localhost:8080"))
                        .build();

        // exercise
        var response = registration.register(req);

        // verify
        assertEquals(400, response.status);
    }

    @Test
    void validationError_applicationTypeIsNativeAndRedirectUriHttps() throws JOSEException {

        // setup
        var es256 = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var config = Fixtures.azIdPConfig(es256.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        new InMemoryAccessTokenService(accessTokenStore));
        var req =
                ClientRegistrationRequest.builder()
                        .applicationType("native")
                        .redirectUris(Set.of("https://localhost:8080"))
                        .build();

        // exercise
        var response = registration.register(req);

        // verify
        assertEquals(400, response.status);
    }

    @Test
    void validationError_applicationTypeIsNativeAndRedirectUriNotLocalhost() throws JOSEException {

        // setup
        var es256 = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var config = Fixtures.azIdPConfig(es256.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        new InMemoryAccessTokenService(accessTokenStore));
        var req =
                ClientRegistrationRequest.builder()
                        .applicationType("native")
                        .redirectUris(Set.of("http://example.com"))
                        .build();

        // exercise
        var response = registration.register(req);

        // verify
        assertEquals(400, response.status);
    }

    @Test
    void validationError_IllegalInitiateLoginUri() throws JOSEException {

        // setup
        var es256 = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var config = Fixtures.azIdPConfig(es256.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        new InMemoryAccessTokenService(accessTokenStore));
        var req =
                ClientRegistrationRequest.builder().initiateLoginUri("http://example.com").build();

        // exercise
        var response = registration.register(req);

        // verify
        assertEquals(400, response.status);
    }
}
