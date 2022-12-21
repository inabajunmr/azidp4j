package org.azidp4j.discovery;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.util.List;
import java.util.Set;
import org.azidp4j.AzIdP;
import org.azidp4j.authorize.request.CodeChallengeMethod;
import org.azidp4j.authorize.request.Display;
import org.azidp4j.authorize.request.ResponseMode;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.SigningAlgorithm;
import org.azidp4j.client.TokenEndpointAuthMethod;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.junit.jupiter.api.Test;

class DiscoveryTest {

    @Test
    void all() throws JOSEException {
        // setup
        var discovery =
                DiscoveryConfig.builder()
                        .authorizationEndpoint("http://localhost:8080/authorize")
                        .tokenEndpoint("http://localhost:8080/token")
                        .jwksEndpoint("http://localhost:8080/.well-known/jwks.json")
                        .clientRegistrationEndpoint("http://localhost:8080/client")
                        .userInfoEndpoint("http://localhost:8080/userinfo")
                        .revocationEndpoint("http://localhost:8080/revoke")
                        .introspectionEndpoint("http://localhost:8080/introspect")
                        .displayValueSupported(Set.of(Display.page, Display.popup))
                        .userinfoSigningAlgValuesSupported(Set.of("RS256", "ES256"))
                        .userinfoEncryptionAlgValuesSupported(Set.of("RSA1_5", "RSA-OAEP"))
                        .userinfoEncryptionEncValuesSupported(
                                Set.of("A128CBC-HS256", "A192CBC-HS384"))
                        .serviceDocumentation("https://example.com/service/documentation")
                        .uiLocalesSupported(List.of("sq-AL", "ar-DZ"))
                        .opPolicyUri("https://example.com/policy")
                        .opTosUri("https://example.com/tos")
                        .build();
        var es256 =
                new ECKeyGenerator(Curve.P_256)
                        .keyID("123")
                        .algorithm(new Algorithm("ES256"))
                        .generate();
        var azidp =
                AzIdP.initInMemory()
                        .jwkSet(new JWKSet(es256))
                        .idTokenKidSupplier((alg) -> "123")
                        .idTokenSigningAlgValuesSupported(Set.of(SigningAlgorithm.ES256))
                        .issuer("http://localhost:8080")
                        .grantTypesSupported(
                                Set.of(
                                        GrantType.authorization_code,
                                        GrantType.implicit,
                                        GrantType.refresh_token,
                                        GrantType.password,
                                        GrantType.client_credentials))
                        .responseTypesSupported(
                                Set.of(
                                        Set.of(ResponseType.none),
                                        Set.of(ResponseType.code, ResponseType.token)))
                        .responseModesSupported(Set.of(ResponseMode.query))
                        .scopesSupported(
                                Set.of("openid", "rs:scope1", "rs:scope2", "rs:scope3", "default"))
                        .defaultScopes(Set.of("openid", "rs:scope1"))
                        .tokenEndpointAuthMethodsSupported(
                                Set.of(
                                        TokenEndpointAuthMethod.client_secret_jwt,
                                        TokenEndpointAuthMethod.client_secret_basic))
                        .tokenEndpointAuthSigningAlgValuesSupported(Set.of("RS256"))
                        .introspectionEndpointAuthMethodsSupported(
                                Set.of(
                                        TokenEndpointAuthMethod.client_secret_jwt,
                                        TokenEndpointAuthMethod.private_key_jwt))
                        .introspectionEndpointAuthSigningAlgValuesSupported(Set.of("ES256"))
                        .revocationEndpointAuthMethodsSupported(
                                Set.of(
                                        TokenEndpointAuthMethod.private_key_jwt,
                                        TokenEndpointAuthMethod.client_secret_basic))
                        .revocationEndpointAuthSigningAlgValuesSupported(Set.of("RS256", "ES256"))
                        .discovery(discovery)
                        .customScopeAudienceMapper(new SampleScopeAudienceMapper())
                        .userPasswordVerifier((username, password) -> true)
                        .build();

        // exercise
        var actual = azidp.discovery();

        // verify
        assertEquals("http://localhost:8080", actual.get("issuer"));
        assertEquals("http://localhost:8080/authorize", actual.get("authorization_endpoint"));
        assertEquals("http://localhost:8080/token", actual.get("token_endpoint"));
        assertEquals("http://localhost:8080/.well-known/jwks.json", actual.get("jwks_uri"));
        assertEquals("http://localhost:8080/client", actual.get("registration_endpoint"));
        assertEquals(
                Set.of("openid", "rs:scope1", "rs:scope2", "rs:scope3", "default"),
                actual.get("scopes_supported"));
        assertEquals(Set.of("none", "code token"), actual.get("response_types_supported"));
        assertEquals(Set.of(ResponseMode.query), actual.get("response_modes_supported"));
        assertEquals(
                Set.of(
                        GrantType.authorization_code,
                        GrantType.implicit,
                        GrantType.refresh_token,
                        GrantType.password,
                        GrantType.client_credentials),
                actual.get("grant_types_supported"));
        assertEquals(
                Set.of(
                        TokenEndpointAuthMethod.client_secret_jwt,
                        TokenEndpointAuthMethod.client_secret_basic),
                actual.get("token_endpoint_auth_methods_supported"));
        assertEquals(
                Set.of("RS256"), actual.get("token_endpoint_auth_signing_alg_values_supported"));
        assertEquals(
                "https://example.com/service/documentation", actual.get("service_documentation"));
        assertEquals(List.of("sq-AL", "ar-DZ"), actual.get("ui_locales_supported"));
        assertEquals("https://example.com/policy", actual.get("op_policy_uri"));
        assertEquals("https://example.com/tos", actual.get("op_tos_uri"));
        assertEquals("http://localhost:8080/revoke", actual.get("revocation_endpoint"));
        assertEquals(
                Set.of(
                        TokenEndpointAuthMethod.private_key_jwt,
                        TokenEndpointAuthMethod.client_secret_basic),
                actual.get("revocation_endpoint_auth_methods_supported"));
        assertEquals(
                Set.of("RS256", "ES256"),
                actual.get("revocation_endpoint_auth_signing_alg_values_supported"));
        assertEquals("http://localhost:8080/introspect", actual.get("introspection_endpoint"));
        assertEquals(
                Set.of(
                        TokenEndpointAuthMethod.client_secret_jwt,
                        TokenEndpointAuthMethod.private_key_jwt),
                actual.get("introspection_endpoint_auth_methods_supported"));
        assertEquals(
                Set.of("ES256"),
                actual.get("introspection_endpoint_auth_signing_alg_values_supported"));
        assertEquals(
                Set.of(CodeChallengeMethod.PLAIN.name(), CodeChallengeMethod.S256.name()),
                actual.get("code_challenge_methods_supported"));
        assertEquals("http://localhost:8080/userinfo", actual.get("userinfo_endpoint"));
        assertEquals(Set.of("public"), actual.get("subject_types_supported"));
        assertEquals(
                Set.of(SigningAlgorithm.ES256),
                actual.get("id_token_signing_alg_values_supported"));
        assertEquals(Set.of(), actual.get("id_token_encryption_alg_values_supported"));
        assertEquals(Set.of(), actual.get("id_token_encryption_enc_values_supported"));
        assertEquals(Set.of("RS256", "ES256"), actual.get("userinfo_signing_alg_values_supported"));
        assertEquals(
                Set.of("RSA1_5", "RSA-OAEP"),
                actual.get("userinfo_encryption_alg_values_supported"));
        assertEquals(
                Set.of("A128CBC-HS256", "A192CBC-HS384"),
                actual.get("userinfo_encryption_enc_values_supported"));
        assertNull(actual.get("request_object_signing_alg_values_supported"));
        assertNull(actual.get("request_object_encryption_alg_values_supported"));
        assertNull(actual.get("request_object_encryption_enc_values_supported"));
        assertEquals(Set.of(Display.page, Display.popup), actual.get("display_values_supported"));
    }
}
