package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AccessTokenAssert;
import org.azidp4j.Fixtures;
import org.azidp4j.IdTokenAssert;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeStore;
import org.azidp4j.authorize.request.InternalAuthorizationRequest;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.authorize.response.NextAction;
import org.azidp4j.client.*;
import org.azidp4j.client.TokenEndpointAuthMethod;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.junit.jupiter.api.Test;

class AuthorizeTest_Implicit {

    final ClientStore clientStore = new InMemoryClientStore();
    final Client clientEs256 =
            new Client(
                    "client1",
                    "clientSecret",
                    Set.of("http://rp1.example.com", "http://rp2.example.com"),
                    Set.of(GrantType.authorization_code),
                    Set.of(ResponseType.code),
                    "scope1 scope2 openid",
                    TokenEndpointAuthMethod.client_secret_basic,
                    SigningAlgorithm.ES256);

    final Client noGrantTypesClient =
            new Client(
                    "noGrantTypesClient",
                    "clientSecret",
                    Set.of("http://rp1.example.com"),
                    Set.of(),
                    Set.of(ResponseType.code),
                    "scope1 scope2",
                    TokenEndpointAuthMethod.client_secret_basic,
                    SigningAlgorithm.ES256);

    final Client noResponseTypesClient =
            new Client(
                    "noResponseTypesClient",
                    "clientSecret",
                    Set.of("http://rp1.example.com"),
                    Set.of(GrantType.authorization_code, GrantType.implicit),
                    Set.of(),
                    "scope1 scope2",
                    TokenEndpointAuthMethod.client_secret_basic,
                    SigningAlgorithm.ES256);

    public AuthorizeTest_Implicit() {
        clientStore.save(clientEs256);
        clientStore.save(noGrantTypesClient);
        clientStore.save(noResponseTypesClient);
    }

    @Test
    void implicitGrant_withoutState() throws JOSEException {
        // setup
        var clientStore = new InMemoryClientStore();
        var client =
                new Client(
                        "client1",
                        "clientSecret",
                        Set.of("http://rp1.example.com", "http://rp2.example.com"),
                        Set.of(GrantType.implicit),
                        Set.of(ResponseType.token),
                        "rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        SigningAlgorithm.ES256);
        clientStore.save(client);
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var scopeAudienceMapper = new SampleScopeAudienceMapper();
        var accessTokenStore = new InMemoryAccessTokenStore();
        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                        scopeAudienceMapper,
                        new InMemoryAccessTokenService(accessTokenStore),
                        new IDTokenIssuer(config, new JWKSet()),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect.redirectTo;
        var fragmentMap =
                Arrays.stream(URI.create(location).getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertNull(fragmentMap.get("state"));
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find(fragmentMap.get("access_token")).get(),
                "username",
                "http://rs.example.com",
                "client1",
                "rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
    }

    @Test
    void implicitGrant_withState() throws JOSEException {
        // setup
        var clientStore = new InMemoryClientStore();
        var client =
                new Client(
                        "client1",
                        "clientSecret",
                        Set.of("http://rp1.example.com", "http://rp2.example.com"),
                        Set.of(GrantType.implicit),
                        Set.of(ResponseType.token),
                        "rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        SigningAlgorithm.ES256);
        clientStore.save(client);
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var scopeAudienceMapper = new SampleScopeAudienceMapper();
        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                        scopeAudienceMapper,
                        new InMemoryAccessTokenService(accessTokenStore),
                        new IDTokenIssuer(config, new JWKSet()),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token")
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
    }

    @Test
    void implicitGrant_oidc_es256_withState() throws JOSEException, ParseException {
        // setup
        var clientStore = new InMemoryClientStore();
        var client =
                new Client(
                        "client1",
                        "clientSecret",
                        Set.of("http://rp1.example.com", "http://rp2.example.com"),
                        Set.of(GrantType.implicit),
                        Set.of(ResponseType.token, ResponseType.id_token),
                        "openid rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        SigningAlgorithm.ES256);
        clientStore.save(client);
        var key =
                new ECKeyGenerator(Curve.P_256)
                        .keyID("123")
                        .algorithm(new Algorithm("ES256"))
                        .generate();
        var jwks = new JWKSet(key);
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var scopeAudienceMapper = new SampleScopeAudienceMapper();
        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                        scopeAudienceMapper,
                        new InMemoryAccessTokenService(accessTokenStore),
                        new IDTokenIssuer(config, jwks),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token id_token")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("openid rs:scope1")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("openid", "rs:scope1", "rs:scope2"))
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
                "openid rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
        IdTokenAssert.assertIdTokenES256(
                fragmentMap.get("id_token"),
                key,
                "username",
                "client1",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                null,
                fragmentMap.get("access_token"),
                null);
    }

    @Test
    void implicitGrant_oidc_rs256_withState() throws JOSEException, ParseException {
        // setup
        var clientStore = new InMemoryClientStore();
        var client =
                new Client(
                        "client1",
                        "clientSecret",
                        Set.of("http://rp1.example.com", "http://rp2.example.com"),
                        Set.of(GrantType.implicit),
                        Set.of(ResponseType.token, ResponseType.id_token),
                        "openid rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        SigningAlgorithm.RS256);
        clientStore.save(client);
        var ecKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID("123")
                        .algorithm(new Algorithm("ES256"))
                        .generate();
        var rsaKey =
                new RSAKeyGenerator(2048).keyID("123").algorithm(new Algorithm("RS256")).generate();
        var jwks = new JWKSet(List.of(ecKey, rsaKey));
        var config = Fixtures.azIdPConfig(ecKey.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var scopeAudienceMapper = new SampleScopeAudienceMapper();
        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                        scopeAudienceMapper,
                        new InMemoryAccessTokenService(accessTokenStore),
                        new IDTokenIssuer(config, jwks),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token id_token")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("openid rs:scope1")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("openid", "rs:scope1", "rs:scope2"))
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
                "openid rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
        IdTokenAssert.assertIdTokenRS256(
                fragmentMap.get("id_token"),
                rsaKey,
                "username",
                "client1",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                null,
                fragmentMap.get("access_token"),
                null);
    }

    @Test
    void implicitGrant_oidc_none_withState() throws JOSEException, ParseException {
        // setup
        var clientStore = new InMemoryClientStore();
        var client =
                new Client(
                        "client1",
                        "clientSecret",
                        Set.of("http://rp1.example.com", "http://rp2.example.com"),
                        Set.of(GrantType.implicit),
                        Set.of(ResponseType.token, ResponseType.id_token),
                        "openid rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        SigningAlgorithm.none);
        clientStore.save(client);
        var key =
                new ECKeyGenerator(Curve.P_256)
                        .keyID("123")
                        .algorithm(new Algorithm("ES256"))
                        .generate();
        var jwks = new JWKSet(key);
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var scopeAudienceMapper = new SampleScopeAudienceMapper();
        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                        scopeAudienceMapper,
                        new InMemoryAccessTokenService(accessTokenStore),
                        new IDTokenIssuer(config, jwks),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token id_token")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("openid rs:scope1")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("openid", "rs:scope1", "rs:scope2"))
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
                "openid rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
        IdTokenAssert.assertIdTokenNone(
                fragmentMap.get("id_token"),
                "username",
                "client1",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                null,
                fragmentMap.get("access_token"),
                null);
    }
}
