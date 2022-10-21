package org.azidp4j.oauth2;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AzIdP;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeStore;
import org.azidp4j.authorize.request.AuthorizationRequest;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.authorize.response.NextAction;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.client.request.ClientRegistrationRequest;
import org.azidp4j.introspection.request.IntrospectionRequest;
import org.azidp4j.revocation.request.RevocationRequest;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenService;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenStore;
import org.azidp4j.token.request.TokenRequest;
import org.junit.jupiter.api.Test;

public class SimpleTest {

    /**
     * 1. client registration 2. authorization request(authorization code grant) 3. token
     * request(using authorization code) 4. token request(using refresh token)
     */
    @Test
    void test() throws JOSEException {
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var scopeAudienceMapper = new SampleScopeAudienceMapper();
        var sut =
                new AzIdP(
                        config,
                        jwks,
                        new InMemoryClientStore(),
                        new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                        new InMemoryAccessTokenService(accessTokenStore),
                        new InMemoryRefreshTokenService(new InMemoryRefreshTokenStore()),
                        scopeAudienceMapper);

        // client registration
        var clientRegistrationRequest =
                ClientRegistrationRequest.builder()
                        .redirectUris(Set.of("http://example.com"))
                        .grantTypes(
                                Set.of(
                                        GrantType.authorization_code.name(),
                                        GrantType.refresh_token.name()))
                        .responseTypes(Set.of(ResponseType.code.name()))
                        .scope("scope1 scope2")
                        .build();
        var clientRegistrationResponse = sut.registerClient(clientRegistrationRequest);
        var clientId = (String) clientRegistrationResponse.body.get("client_id");

        // authorization request
        var redirectUri = "http://example.com";
        var queryParameters =
                Map.of(
                        "client_id",
                        clientId,
                        "redirect_uri",
                        redirectUri,
                        "response_type",
                        "code",
                        "scope",
                        "scope1 scope2",
                        "state",
                        "xyz");
        var authorizationRequest =
                new AuthorizationRequest(
                        "username",
                        Instant.now().getEpochSecond(),
                        Set.of("scope1", "scope2"),
                        queryParameters);

        // exercise
        var authorizationResponse = sut.authorize(authorizationRequest);

        // verify
        assertEquals(authorizationResponse.next, NextAction.redirect);
        var queryMap =
                Arrays.stream(
                                URI.create(authorizationResponse.redirect.redirectTo)
                                        .getQuery()
                                        .split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(queryMap.get("state"), "xyz");

        // token request
        var tokenRequestBody1 =
                Map.of(
                        "code",
                        queryMap.get("code"),
                        "redirect_uri",
                        redirectUri,
                        "grant_type",
                        "authorization_code");
        var tokenRequest1 = new TokenRequest(clientId, tokenRequestBody1);

        // exercise
        var tokenResponse1 = sut.issueToken(tokenRequest1);

        // verify
        assertNotNull(tokenResponse1.body.get("access_token"));
        var refreshToken = tokenResponse1.body.get("refresh_token");

        // token request
        var tokenRequestBody2 =
                Map.of("refresh_token", (String) refreshToken, "grant_type", "refresh_token");
        var tokenRequest2 = new TokenRequest(clientId, tokenRequestBody2);

        // exercise
        var tokenResponse2 = sut.issueToken(tokenRequest2);

        // verify
        var accessToken = (String) tokenResponse2.body.get("access_token");
        assertNotNull(accessToken);

        // introspection
        var introspectionResponse1 =
                sut.introspect(
                        new IntrospectionRequest(
                                Map.of("token", accessToken, "token_type_hint", "access_token")));

        // verify
        assertEquals(200, introspectionResponse1.status);
        assertEquals(true, introspectionResponse1.body.get("active"));

        // revocation
        // exercise
        var revocationResponse =
                sut.revoke(
                        new RevocationRequest(
                                clientId,
                                Map.of(
                                        "token",
                                        (String) tokenResponse2.body.get("access_token"),
                                        "token_type_hint",
                                        "access_token")));

        // verify
        assertEquals(200, revocationResponse.status);

        // introspection
        var introspectionResponse2 =
                sut.introspect(
                        new IntrospectionRequest(
                                Map.of("token", accessToken, "token_type_hint", "access_token")));

        // verify
        assertEquals(200, introspectionResponse2.status);
        assertEquals(false, introspectionResponse2.body.get("active"));
    }
}
