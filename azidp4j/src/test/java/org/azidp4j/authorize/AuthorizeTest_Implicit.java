package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
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
import org.azidp4j.token.SampleIdTokenKidSupplier;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenValidator;
import org.junit.jupiter.api.Test;

class AuthorizeTest_Implicit {

    final ClientStore clientStore = new InMemoryClientStore();
    final ECKey eckey =
            new ECKeyGenerator(Curve.P_256)
                    .algorithm(new Algorithm("ES256"))
                    .keyID("123")
                    .generate();
    final RSAKey rsaKey =
            new RSAKeyGenerator(2048).keyID("abc").algorithm(new Algorithm("RS256")).generate();

    final Client clientEs256 =
            new Client(
                    "es256client",
                    "clientSecret",
                    Set.of("http://rp1.example.com", "http://rp2.example.com"),
                    Set.of(
                            Set.of(ResponseType.token),
                            Set.of(ResponseType.token, ResponseType.id_token)),
                    ApplicationType.WEB,
                    Set.of(GrantType.authorization_code, GrantType.implicit),
                    null,
                    null,
                    null,
                    "rs:scope1 rs:scope2 openid",
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    TokenEndpointAuthMethod.client_secret_basic,
                    null,
                    SigningAlgorithm.ES256,
                    null,
                    null,
                    null);

    final Client clientRs256 =
            new Client(
                    "rs256client",
                    "clientSecret",
                    Set.of("http://rp1.example.com", "http://rp2.example.com"),
                    Set.of(Set.of(ResponseType.token, ResponseType.id_token)),
                    ApplicationType.WEB,
                    Set.of(GrantType.implicit),
                    null,
                    null,
                    null,
                    "openid rs:scope1 rs:scope2",
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    TokenEndpointAuthMethod.client_secret_basic,
                    null,
                    SigningAlgorithm.RS256,
                    null,
                    null,
                    null);

    final Client noGrantTypesClient =
            new Client(
                    "noGrantTypesClient",
                    "clientSecret",
                    Set.of("http://rp1.example.com"),
                    Set.of(Set.of(ResponseType.code)),
                    ApplicationType.WEB,
                    Set.of(),
                    null,
                    null,
                    null,
                    "scope1 scope2",
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    TokenEndpointAuthMethod.client_secret_basic,
                    null,
                    SigningAlgorithm.ES256,
                    null,
                    null,
                    null);

    final Client noResponseTypesClient =
            new Client(
                    "noResponseTypesClient",
                    "clientSecret",
                    Set.of("http://rp1.example.com"),
                    Set.of(),
                    ApplicationType.WEB,
                    Set.of(GrantType.authorization_code, GrantType.implicit),
                    null,
                    null,
                    null,
                    "scope1 scope2",
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    TokenEndpointAuthMethod.client_secret_basic,
                    null,
                    SigningAlgorithm.ES256,
                    null,
                    null,
                    null);

    final Authorize sut;
    final InMemoryAccessTokenStore accessTokenStore;

    public AuthorizeTest_Implicit() throws JOSEException {
        var config = Fixtures.azIdPConfig();
        var scopeAudienceMapper = new SampleScopeAudienceMapper();
        this.accessTokenStore = new InMemoryAccessTokenStore();
        var jwks = new JWKSet(List.of(rsaKey, eckey));
        this.sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                        scopeAudienceMapper,
                        new InMemoryAccessTokenService(accessTokenStore),
                        new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks), null),
                        new IDTokenValidator(config, jwks),
                        config);

        clientStore.save(clientEs256);
        clientStore.save(clientRs256);
        clientStore.save(noGrantTypesClient);
        clientStore.save(noResponseTypesClient);
    }

    @Test
    void implicitGrant_withoutState() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token")
                        .clientId(clientEs256.clientId)
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
        var fragmentMap =
                Arrays.stream(location.getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertNull(fragmentMap.get("state"));
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find(fragmentMap.get("access_token")).get(),
                "username",
                "http://rs.example.com",
                clientEs256.clientId,
                "rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
    }

    @Test
    void implicitGrant_withState() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token")
                        .clientId(clientEs256.clientId)
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
        var fragmentMap =
                Arrays.stream(location.getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(fragmentMap.get("state"), "xyz");
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find(fragmentMap.get("access_token")).get(),
                "username",
                "http://rs.example.com",
                clientEs256.clientId,
                "rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
    }

    @Test
    void implicitGrant_oidc_es256_withState() throws JOSEException, ParseException {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token id_token")
                        .clientId(clientEs256.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("openid rs:scope1")
                        .authenticatedUserSubject("username")
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
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find(fragmentMap.get("access_token")).get(),
                "username",
                "http://rs.example.com",
                clientEs256.clientId,
                "openid rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
        IdTokenAssert.assertIdTokenES256(
                fragmentMap.get("id_token"),
                eckey,
                "username",
                clientEs256.clientId,
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                "abc",
                fragmentMap.get("access_token"),
                null);
    }

    @Test
    void implicitGrant_oidc_es256_withAcr() throws JOSEException, ParseException {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token id_token")
                        .authenticatedUserAcr("acrValue")
                        .clientId(clientEs256.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("openid rs:scope1")
                        .authenticatedUserSubject("username")
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
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find(fragmentMap.get("access_token")).get(),
                "username",
                "http://rs.example.com",
                clientEs256.clientId,
                "openid rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
        IdTokenAssert.assertIdTokenES256(
                fragmentMap.get("id_token"),
                eckey,
                "username",
                clientEs256.clientId,
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                "abc",
                fragmentMap.get("access_token"),
                null);
        assertEquals(
                JWSObject.parse(fragmentMap.get("id_token")).getPayload().toJSONObject().get("acr"),
                "acrValue");
        ;
    }

    @Test
    void implicitGrant_oidc_rs256_withState() throws JOSEException, ParseException {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token id_token")
                        .clientId(clientRs256.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("openid rs:scope1")
                        .authenticatedUserSubject("username")
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
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find(fragmentMap.get("access_token")).get(),
                "username",
                "http://rs.example.com",
                clientRs256.clientId,
                "openid rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
        IdTokenAssert.assertIdTokenRS256(
                fragmentMap.get("id_token"),
                rsaKey,
                "username",
                clientRs256.clientId,
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                "abc",
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
                        Set.of(Set.of(ResponseType.token, ResponseType.id_token)),
                        ApplicationType.WEB,
                        Set.of(GrantType.implicit),
                        null,
                        null,
                        null,
                        "openid rs:scope1 rs:scope2",
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        TokenEndpointAuthMethod.client_secret_basic,
                        null,
                        SigningAlgorithm.none,
                        null,
                        null,
                        null);
        clientStore.save(client);
        var key =
                new ECKeyGenerator(Curve.P_256)
                        .keyID("123")
                        .algorithm(new Algorithm("ES256"))
                        .generate();
        var jwks = new JWKSet(key);
        var config = Fixtures.azIdPConfig();
        var accessTokenStore = new InMemoryAccessTokenStore();
        var scopeAudienceMapper = new SampleScopeAudienceMapper();
        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                        scopeAudienceMapper,
                        new InMemoryAccessTokenService(accessTokenStore),
                        new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks), null),
                        new IDTokenValidator(config, jwks),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token id_token")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("openid rs:scope1")
                        .authenticatedUserSubject("username")
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
                "abc",
                fragmentMap.get("access_token"),
                null);
    }
}
