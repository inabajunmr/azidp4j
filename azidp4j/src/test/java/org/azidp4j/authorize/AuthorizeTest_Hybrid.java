package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AccessTokenAssert;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.IdTokenAssert;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeStore;
import org.azidp4j.authorize.request.InternalAuthorizationRequest;
import org.azidp4j.authorize.response.NextAction;
import org.azidp4j.client.*;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.token.SampleIdTokenKidSupplier;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenValidator;
import org.junit.jupiter.api.Test;

class AuthorizeTest_Hybrid {

    final ClientStore clientStore = new InMemoryClientStore();
    final Client client = Fixtures.confidentialClient().build();

    final ECKey key =
            new ECKeyGenerator(Curve.P_256)
                    .keyID("123")
                    .algorithm(new Algorithm("ES256"))
                    .generate();
    final JWKSet jwks = new JWKSet(key);
    final AzIdPConfig config = Fixtures.azIdPConfig();
    final ScopeAudienceMapper scopeAudienceMapper = new SampleScopeAudienceMapper();
    final AccessTokenService accessTokenService =
            new InMemoryAccessTokenService(new InMemoryAccessTokenStore());

    final Authorize sut =
            new Authorize(
                    clientStore,
                    new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                    scopeAudienceMapper,
                    accessTokenService,
                    new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks), null),
                    new IDTokenValidator(config, jwks),
                    config);

    public AuthorizeTest_Hybrid() throws JOSEException {
        clientStore.save(client);
    }

    @Test
    void codeAndToken() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code token")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("https://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserSubject("username")
                        .authenticatedUserAcr("acr1")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .state("xyz")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        var fragmentMap =
                Arrays.stream(location.getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(fragmentMap.get("state"), "xyz");
        AccessTokenAssert.assertAccessToken(
                accessTokenService.introspect(fragmentMap.get("access_token")).get(),
                "username",
                "http://rs.example.com",
                client.clientId,
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
                        .redirectUri("https://rp1.example.com")
                        .scope("openid rs:scope1")
                        .authenticatedUserSubject("username")
                        .authenticatedUserAcr("acr1")
                        .consentedScope(Set.of("openid", "rs:scope1", "rs:scope2"))
                        .state("xyz")
                        .nonce("abc")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        var fragmentMap =
                Arrays.stream(location.getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(fragmentMap.get("state"), "xyz");
        IdTokenAssert.assertIdTokenES256(
                fragmentMap.get("id_token"),
                key,
                "username",
                client.clientId,
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
                        .redirectUri("https://rp1.example.com")
                        .scope("openid rs:scope1")
                        .authenticatedUserSubject("username")
                        .authenticatedUserAcr("acr1")
                        .consentedScope(Set.of("openid", "rs:scope1", "rs:scope2"))
                        .state("xyz")
                        .nonce("abc")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        var fragmentMap =
                Arrays.stream(location.getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(fragmentMap.get("state"), "xyz");
        IdTokenAssert.assertIdTokenES256(
                fragmentMap.get("id_token"),
                key,
                "username",
                client.clientId,
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                "abc",
                fragmentMap.get("access_token"),
                null);
        AccessTokenAssert.assertAccessToken(
                accessTokenService.introspect(fragmentMap.get("access_token")).get(),
                "username",
                "http://rs.example.com",
                client.clientId,
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
                        .redirectUri("https://rp1.example.com")
                        .scope("openid rs:scope1")
                        .authenticatedUserSubject("username")
                        .authenticatedUserAcr("acr1")
                        .consentedScope(Set.of("openid", "rs:scope1", "rs:scope2"))
                        .state("xyz")
                        .nonce("abc")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        var fragmentMap =
                Arrays.stream(location.getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(fragmentMap.get("state"), "xyz");
        IdTokenAssert.assertIdTokenES256(
                fragmentMap.get("id_token"),
                key,
                "username",
                client.clientId,
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                "abc",
                fragmentMap.get("access_token"),
                fragmentMap.get("id_token"));
        AccessTokenAssert.assertAccessToken(
                accessTokenService.introspect(fragmentMap.get("access_token")).get(),
                "username",
                "http://rs.example.com",
                client.clientId,
                "openid rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
        assertNotNull(fragmentMap.get("code"));
    }
}
