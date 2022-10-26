package org.azidp4j.client;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.azidp4j.Fixtures;
import org.azidp4j.client.request.ClientConfigurationRequest;
import org.azidp4j.client.request.ClientRegistrationRequest;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.util.HumanReadable;
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
                        new InMemoryAccessTokenService(new InMemoryAccessTokenStore()));
        var registrationResponse = registration.register(registerAll());
        var configurationRequest =
                ClientConfigurationRequest.builder()
                        .clientId(registrationResponse.body.get("client_id").toString())
                        .redirectUris(
                                Set.of(
                                        "http://client.example.com/callback1/new",
                                        "http://client.example.com/callback2/new"))
                        .grantTypes(
                                Set.of(
                                        "authorization_code",
                                        "implicit",
                                        "password", // add
                                        "refresh_token",
                                        "client_credentials"))
                        .responseTypes(Set.of("code", "token", "id_token", "none"))
                        .clientName(
                                new HumanReadable<>(
                                        "client_name",
                                        "client/new",
                                        Map.of("ja", "クライアント/new", "cn", "客户/new")))
                        .clientUri("http://client.example.com/new")
                        .logoUri("http://client.example.com/logo/new")
                        .scope("scope1 scope2 scope3")
                        .contacts(List.of("hello", "world", "new"))
                        .tosUri(
                                new HumanReadable<>(
                                        "tos_uri",
                                        "http://client.example.com/tos/new",
                                        Map.of(
                                                "ja",
                                                "http://client.example.com/tos/ja/new",
                                                "cn",
                                                "http://client.example.com/tos/cn/new")))
                        .policyUri(
                                new HumanReadable<>(
                                        "policy_uri",
                                        "http://client.example.com/policy/new",
                                        Map.of(
                                                "ja",
                                                "http://client.example.com/policy/ja/new",
                                                "cn",
                                                "http://client.example.com/policy/cn/new")))
                        .jwksUri("http://client.example.com/jwks/new")
                        .softwareId("azidp/new")
                        .softwareVersion("1.0.1")
                        .tokenEndpointAuthMethod("client_secret_post")
                        .idTokenSignedResponseAlg("ES256")
                        .build();

        // exercise
        var response = registration.configure(configurationRequest);

        // verify
        assertEquals(200, response.status);
        assertEquals(response.body.get("client_id"), registrationResponse.body.get("client_id"));
        assertEquals(
                response.body.get("redirect_uris"),
                Set.of(
                        "http://client.example.com/callback1/new",
                        "http://client.example.com/callback2/new"));
        assertEquals(
                response.body.get("grant_types"),
                Set.of(
                        "authorization_code",
                        "implicit",
                        "refresh_token",
                        "client_credentials",
                        "password"));
        assertEquals(
                response.body.get("response_types"), Set.of("code", "token", "id_token", "none"));
        assertEquals(
                response.body.get("client_name"),
                Map.of(
                        "client_name",
                        "client/new",
                        "client_name#ja",
                        "クライアント/new",
                        "client_name#cn",
                        "客户/new"));
        assertEquals(response.body.get("client_uri"), "http://client.example.com/new");
        assertEquals(response.body.get("logo_uri"), "http://client.example.com/logo/new");
        assertEquals(response.body.get("scope"), "scope1 scope2 scope3");
        assertEquals(response.body.get("contacts"), List.of("hello", "world", "new"));
        assertEquals(
                response.body.get("tos_uri"),
                Map.of(
                        "tos_uri",
                        "http://client.example.com/tos/new",
                        "tos_uri#ja",
                        "http://client.example.com/tos/ja/new",
                        "tos_uri#cn",
                        "http://client.example.com/tos/cn/new"));
        assertEquals(
                response.body.get("policy_uri"),
                Map.of(
                        "policy_uri",
                        "http://client.example.com/policy/new",
                        "policy_uri#ja",
                        "http://client.example.com/policy/ja/new",
                        "policy_uri#cn",
                        "http://client.example.com/policy/cn/new"));
        assertEquals(response.body.get("jwks_uri"), "http://client.example.com/jwks/new");
        assertEquals(response.body.get("software_id"), "azidp/new");
        assertEquals(response.body.get("software_version"), "1.0.1");
        assertEquals(response.body.get("token_endpoint_auth_method"), "client_secret_post");
        assertEquals(response.body.get("id_token_signed_response_alg"), "ES256");
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
                        new InMemoryAccessTokenService(new InMemoryAccessTokenStore()));
        var registrationResponse = registration.register(registerAll());
        var configurationRequest =
                ClientConfigurationRequest.builder()
                        .clientId(registrationResponse.body.get("client_id").toString())
                        .build();

        // exercise
        var response = registration.configure(configurationRequest);

        // verify
        assertEquals(response.status, 200);
        assertEquals(response.body.get("client_id"), registrationResponse.body.get("client_id"));
        assertEquals(
                response.body.get("redirect_uris"),
                Set.of(
                        "http://client.example.com/callback1",
                        "http://client.example.com/callback2"));
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
        assertEquals(response.body.get("jwks_uri"), "http://client.example.com/jwks");
        assertEquals(response.body.get("software_id"), "azidp");
        assertEquals(response.body.get("software_version"), "1.0.0");
        assertEquals(response.body.get("token_endpoint_auth_method"), "client_secret_basic");
        assertEquals(response.body.get("id_token_signed_response_alg"), "RS256");
    }

    @Test
    void validationError_JwksAndJwksUri() throws JOSEException {
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var registration =
                new DynamicClientRegistration(
                        config,
                        new InMemoryClientStore(),
                        new InMemoryAccessTokenService(new InMemoryAccessTokenStore()));
        var registrationResponse = registration.register(registerAll());
        var configurationRequest =
                ClientConfigurationRequest.builder()
                        .clientId(registrationResponse.body.get("client_id").toString())
                        .jwks("jwks")
                        .build();

        // exercise
        var response = registration.configure(configurationRequest);

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
                        new InMemoryAccessTokenService(new InMemoryAccessTokenStore()));
        var registrationResponse = registration.register(registerAll());
        var configurationRequest =
                ClientConfigurationRequest.builder()
                        .clientId(registrationResponse.body.get("client_id").toString())
                        .grantTypes(Set.of("client_credentials"))
                        .tokenEndpointAuthMethod("none")
                        .build();

        // exercise
        var response = registration.configure(configurationRequest);

        // verify
        assertEquals(response.status, 400);
    }

    private ClientRegistrationRequest registerAll() {
        return ClientRegistrationRequest.builder()
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
                .responseTypes(Set.of("code", "token", "id_token"))
                .clientName(new HumanReadable<>("client_name", "client", Map.of("ja", "クライアント")))
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
                .idTokenSignedResponseAlg("RS256")
                .build();
    }
}
