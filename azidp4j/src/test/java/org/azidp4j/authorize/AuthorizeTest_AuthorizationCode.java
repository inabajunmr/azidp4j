package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.jwk.JWKSet;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeStore;
import org.azidp4j.authorize.request.InternalAuthorizationRequest;
import org.azidp4j.authorize.response.NextAction;
import org.azidp4j.client.*;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.token.SampleIdTokenKidSupplier;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenValidator;
import org.junit.jupiter.api.Test;

class AuthorizeTest_AuthorizationCode {

    final ClientStore clientStore = new InMemoryClientStore();
    final Client client = Fixtures.confidentialClient();
    final Client noGrantTypesClient = Fixtures.noGrantTypeClient();
    final Client noResponseTypesClient = Fixtures.noResponseTypeClient();
    final AzIdPConfig config = Fixtures.azIdPConfig();
    final ScopeAudienceMapper scopeAudienceMapper = new SampleScopeAudienceMapper();
    final JWKSet jwks = new JWKSet();
    final Authorize sut =
            new Authorize(
                    clientStore,
                    new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                    scopeAudienceMapper,
                    new InMemoryAccessTokenService(new InMemoryAccessTokenStore()),
                    new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks), null),
                    new IDTokenValidator(config, jwks),
                    config);

    public AuthorizeTest_AuthorizationCode() {
        clientStore.save(client);
        clientStore.save(noGrantTypesClient);
        clientStore.save(noResponseTypesClient);
    }

    @Test
    void authorizationCodeGrant_withoutState() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertNull(queryMap.get("state"));
        assertNotNull(queryMap.get("code"));
    }

    @Test
    void authorizationCodeGrant_withState() {
        // setup
        var clientStore = new InMemoryClientStore();
        clientStore.save(client);
        var config = Fixtures.azIdPConfig();
        var scopeAudienceMapper = new SampleScopeAudienceMapper();
        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                        scopeAudienceMapper,
                        new InMemoryAccessTokenService(new InMemoryAccessTokenStore()),
                        new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks), null),
                        new IDTokenValidator(config, jwks),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .state("xyz")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(queryMap.get("state"), "xyz");
        assertNotNull(queryMap.get("code"));
    }

    @Test
    void authorizationCodeGrant_withoutScope() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope(null)
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("openid", "rs:scope1"))
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertNull(queryMap.get("state"));
        assertNotNull(queryMap.get("code"));
    }

    @Test
    void authorizationCodeGrant_withMaxAge() {
        // setup
        var clientStore = new InMemoryClientStore();
        clientStore.save(client);
        var config = Fixtures.azIdPConfig();

        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                        scopeAudienceMapper,
                        new InMemoryAccessTokenService(new InMemoryAccessTokenStore()),
                        new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks), null),
                        new IDTokenValidator(config, jwks),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .maxAge("10")
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .state("xyz")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(queryMap.get("state"), "xyz");
        assertNotNull(queryMap.get("code"));
    }

    @Test
    void authorizationCodeGrant_fragment() {
        // setup
        var clientStore = new InMemoryClientStore();
        clientStore.save(client);
        var config = Fixtures.azIdPConfig();
        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                        scopeAudienceMapper,
                        new InMemoryAccessTokenService(new InMemoryAccessTokenStore()),
                        new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks), null),
                        new IDTokenValidator(config, jwks),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .responseMode("fragment")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .maxAge("10")
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .state("xyz")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        var queryMap =
                Arrays.stream(location.getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(queryMap.get("state"), "xyz");
        assertNotNull(queryMap.get("code"));
    }
}
