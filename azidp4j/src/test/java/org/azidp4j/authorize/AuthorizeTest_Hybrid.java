package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AccessTokenAssert;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.IdTokenAssert;
import org.azidp4j.authorize.request.InternalAuthorizationRequest;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.authorize.response.NextAction;
import org.azidp4j.client.*;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.TokenEndpointAuthMethod;
import org.azidp4j.token.accesstoken.AccessTokenStore;
import org.azidp4j.token.accesstoken.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.junit.jupiter.api.Test;

class AuthorizeTest_Hybrid {

    ClientStore clientStore = new InMemoryClientStore();
    Client client =
            new Client(
                    "client1",
                    "clientSecret",
                    Set.of("http://rp1.example.com", "http://rp2.example.com"),
                    Set.of(GrantType.authorization_code, GrantType.implicit),
                    Set.of(ResponseType.code, ResponseType.token, ResponseType.id_token),
                    "rs:scope1 rs:scope2 openid",
                    TokenEndpointAuthMethod.client_secret_basic,
                    SigningAlgorithm.ES256);

    ECKey key =
            new ECKeyGenerator(Curve.P_256)
                    .keyID("123")
                    .algorithm(new Algorithm("ES256"))
                    .generate();
    JWKSet jwks = new JWKSet(key);
    AzIdPConfig config = Fixtures.azIdPConfig(key.getKeyID());
    AccessTokenStore accessTokenStore = new InMemoryAccessTokenStore();
    Authorize sut =
            new Authorize(
                    clientStore,
                    new InMemoryAuthorizationCodeStore(),
                    accessTokenStore,
                    new SampleScopeAudienceMapper(),
                    new IDTokenIssuer(config, jwks),
                    config);

    public AuthorizeTest_Hybrid() throws JOSEException {
        clientStore.save(client);
    }

    @Test
    void codeAndToken() throws JOSEException, ParseException {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code token")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .state("xyz")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect.redirectTo;
        var fragmentMap =
                Arrays.stream(URI.create(location).getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(fragmentMap.get("state"), "xyz");
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find(fragmentMap.get("access_token")).get(),
                "username",
                "http://rs.example.com",
                "client1",
                "rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
        assertNotNull(fragmentMap.get("code"));
    }

    @Test
    void codeAndIdToken() throws JOSEException, ParseException {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code id_token")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("openid rs:scope1")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("openid", "rs:scope1", "rs:scope2"))
                        .state("xyz")
                        .nonce("abc")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect.redirectTo;
        var fragmentMap =
                Arrays.stream(URI.create(location).getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(fragmentMap.get("state"), "xyz");
        IdTokenAssert.assertIdTokenES256(
                fragmentMap.get("id_token"),
                key,
                "username",
                "client1",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                "abc",
                null,
                fragmentMap.get("code"));

        assertNull(fragmentMap.get("token_type"));
        assertNull(fragmentMap.get("expires_in"));
        assertNotNull(fragmentMap.get("code"));
    }

    @Test
    void idTokenAndToken() throws JOSEException, ParseException {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("id_token token")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("openid rs:scope1")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("openid", "rs:scope1", "rs:scope2"))
                        .state("xyz")
                        .nonce("abc")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect.redirectTo;
        var fragmentMap =
                Arrays.stream(URI.create(location).getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(fragmentMap.get("state"), "xyz");
        IdTokenAssert.assertIdTokenES256(
                fragmentMap.get("id_token"),
                key,
                "username",
                "client1",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                "abc",
                fragmentMap.get("access_token"),
                null);
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find(fragmentMap.get("access_token")).get(),
                "username",
                "http://rs.example.com",
                "client1",
                "openid rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
        assertNull(fragmentMap.get("code"));
    }

    @Test
    void codeAndIdTokenAndToken() throws JOSEException, ParseException {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code id_token token")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("openid rs:scope1")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("openid", "rs:scope1", "rs:scope2"))
                        .state("xyz")
                        .nonce("abc")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect.redirectTo;
        var fragmentMap =
                Arrays.stream(URI.create(location).getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(fragmentMap.get("state"), "xyz");
        IdTokenAssert.assertIdTokenES256(
                fragmentMap.get("id_token"),
                key,
                "username",
                "client1",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                "abc",
                fragmentMap.get("access_token"),
                fragmentMap.get("id_token"));
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find(fragmentMap.get("access_token")).get(),
                "username",
                "http://rs.example.com",
                "client1",
                "openid rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
        assertNotNull(fragmentMap.get("code"));
    }
}
