package org.azidp4j.sample;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AzIdP;
import org.azidp4j.authorize.request.AuthorizationRequest;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.authorize.response.NextAction;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.request.ClientRequest;
import org.azidp4j.introspection.request.IntrospectionRequest;
import org.azidp4j.revocation.request.RevocationRequest;
import org.azidp4j.token.request.TokenRequest;
import org.junit.jupiter.api.Test;

public class OidcSample {

    @Test
    void test() throws JOSEException {
        // ==============================================
        // Initialization
        // ==============================================
        var keyId = "123";
        final ECKey key =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(keyId)
                        .algorithm(new Algorithm("ES256"))
                        .generate();
        final JWKSet jwks = new JWKSet(key);
        var oidc =
                AzIdP.initInMemory()
                        .issuer("https://idp.example.com")
                        .jwkSet(jwks)
                        .idTokenKidSupplier((alg) -> keyId)
                        .grantTypesSupported(
                                Set.of(
                                        GrantType.authorization_code,
                                        GrantType.refresh_token,
                                        GrantType.client_credentials))
                        .scopesSupported(Set.of("openid", "user:read", "item:read", "order:read"))
                        .defaultScopes(Set.of("user:read"))
                        .customScopeAudienceMapper(s -> Set.of(s.split(":")[0]))
                        .build();

        // ==============================================
        // client registration
        // ==============================================
        var clientRegistrationRequest =
                new ClientRequest(
                        Map.of(
                                "grant_types",
                                Set.of(
                                        GrantType.authorization_code.name(),
                                        GrantType.refresh_token.name()),
                                "scope",
                                "openid user:read item:read order:read",
                                "redirect_uris",
                                Set.of("https://client.example.com"),
                                "response_types",
                                Set.of(ResponseType.code.name())));

        var clientRegistrationResponse = oidc.registerClient(clientRegistrationRequest);
        var clientId = (String) clientRegistrationResponse.body.get("client_id");

        // ==============================================
        // authorization request
        // ==============================================
        var redirectUri = "https://client.example.com";
        var queryParameters =
                Map.of(
                        "client_id",
                        clientId,
                        "redirect_uri",
                        redirectUri,
                        "response_type",
                        "code",
                        "scope",
                        "openid user:read item:read",
                        "state",
                        "xyz");
        var authorizationRequest =
                new AuthorizationRequest(
                        "username",
                        Instant.now().getEpochSecond(),
                        Set.of("openid", "user:read", "item:read"),
                        queryParameters);

        // exercise
        var authorizationResponse = oidc.authorize(authorizationRequest);

        // verify
        assertEquals(authorizationResponse.next, NextAction.redirect);
        var queryMap =
                Arrays.stream(
                                authorizationResponse
                                        .redirect()
                                        .createRedirectTo()
                                        .getQuery()
                                        .split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(queryMap.get("state"), "xyz");

        // ==============================================
        // token request by authorization code
        // ==============================================
        var tokenRequestBody1 =
                Map.of(
                        "code",
                        (Object) queryMap.get("code"),
                        "redirect_uri",
                        redirectUri,
                        "grant_type",
                        "authorization_code");
        var tokenRequest1 = new TokenRequest(clientId, tokenRequestBody1);

        // exercise
        var tokenResponse1 = oidc.issueToken(tokenRequest1);

        // verify
        assertNotNull(tokenResponse1.body.get("access_token"));
        assertNotNull(tokenResponse1.body.get("id_token"));
        var refreshToken = tokenResponse1.body.get("refresh_token");

        // ==============================================
        // token request by refresh token
        // ==============================================
        var tokenRequestBody2 =
                Map.of("refresh_token", refreshToken, "grant_type", "refresh_token");
        var tokenRequest2 = new TokenRequest(clientId, tokenRequestBody2);

        // exercise
        var tokenResponse2 = oidc.issueToken(tokenRequest2);

        // verify
        var accessToken = (String) tokenResponse2.body.get("access_token");
        assertNotNull(accessToken);
        assertNotNull(tokenResponse1.body.get("id_token"));

        // ==============================================
        // introspection
        // ==============================================
        var introspectionResponse1 =
                oidc.introspect(
                        new IntrospectionRequest(
                                Map.of("token", accessToken, "token_type_hint", "access_token")));

        // verify
        assertEquals(200, introspectionResponse1.status);
        assertEquals(true, introspectionResponse1.body.get("active"));

        // ==============================================
        // revocation
        // ==============================================
        // exercise
        var revocationResponse =
                oidc.revoke(
                        new RevocationRequest(
                                clientId,
                                Map.of(
                                        "token",
                                        tokenResponse2.body.get("access_token"),
                                        "token_type_hint",
                                        "access_token")));

        // verify
        assertEquals(200, revocationResponse.status);

        // ==============================================
        // introspection
        // ==============================================
        var introspectionResponse2 =
                oidc.introspect(
                        new IntrospectionRequest(
                                Map.of("token", accessToken, "token_type_hint", "access_token")));

        // verify
        assertEquals(200, introspectionResponse2.status);
        assertEquals(false, introspectionResponse2.body.get("active"));
    }
}
