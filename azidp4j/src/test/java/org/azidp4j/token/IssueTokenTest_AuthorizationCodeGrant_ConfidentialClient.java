package org.azidp4j.token;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.azidp4j.AccessTokenAssert;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.IdTokenAssert;
import org.azidp4j.authorize.AuthorizationCode;
import org.azidp4j.authorize.AuthorizationCodeStore;
import org.azidp4j.authorize.InMemoryAuthorizationCodeStore;
import org.azidp4j.authorize.ResponseType;
import org.azidp4j.client.Client;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.client.SigningAlgorithm;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.accesstoken.AccessTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.refreshtoken.InMemoryRefreshTokenStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class IssueTokenTest_AuthorizationCodeGrant_ConfidentialClient {

    private final ECKey es256Key;
    private final RSAKey rs256Key;

    {
        try {
            es256Key =
                    new ECKeyGenerator(Curve.P_256)
                            .keyID("123")
                            .algorithm(new Algorithm("ES256"))
                            .generate();
            rs256Key =
                    new RSAKeyGenerator(2048)
                            .keyID("abc")
                            .algorithm(new Algorithm("RS256"))
                            .generate();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private final JWKSet jwks = new JWKSet(List.of(es256Key, rs256Key));

    private AuthorizationCodeStore authorizationCodeStore;

    private IssueToken issueToken;

    private final AzIdPConfig config = Fixtures.azIdPConfig(es256Key.getKeyID());

    @BeforeEach
    void init() {
        authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "ES256Client",
                        "secret",
                        null,
                        Set.of(GrantType.authorization_code),
                        Set.of(ResponseType.code),
                        "openid rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        Set.of(SigningAlgorithm.ES256)));
        clientStore.save(
                new Client(
                        "RS256Client",
                        "secret",
                        null,
                        Set.of(GrantType.authorization_code),
                        Set.of(ResponseType.code),
                        "openid rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        Set.of(SigningAlgorithm.RS256)));
        clientStore.save(
                new Client(
                        "NoneClient",
                        "secret",
                        null,
                        Set.of(GrantType.authorization_code),
                        Set.of(ResponseType.code),
                        "openid rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        Set.of(SigningAlgorithm.none)));
        clientStore.save(
                new Client(
                        "other",
                        "secret",
                        null,
                        Set.of(GrantType.authorization_code),
                        Set.of(ResponseType.code),
                        "openid rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        Set.of(SigningAlgorithm.ES256)));
        issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper()),
                        new IDTokenIssuer(config, jwks),
                        new InMemoryRefreshTokenStore(),
                        null,
                        clientStore,
                        jwks);
    }

    @Test
    void success_oauth2() throws JOSEException, ParseException {

        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                new AuthorizationCode(
                        subject,
                        UUID.randomUUID().toString(),
                        "rs:scope1",
                        "ES256Client",
                        "http://example.com",
                        "xyz",
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        authorizationCodeStore.save(authorizationCode);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .code(authorizationCode.code)
                        .grantType("authorization_code")
                        .redirectUri("http://example.com")
                        .authenticatedClientId("ES256Client")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        AccessTokenAssert.assertAccessToken(
                (String) response.body.get("access_token"),
                es256Key,
                subject,
                "http://rs.example.com",
                "ES256Client",
                "rs:scope1",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond());
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertTrue(response.body.containsKey("refresh_token"));
    }

    @Test
    void success_oidcWithNonceES256() throws JOSEException, ParseException {

        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                new AuthorizationCode(
                        subject,
                        UUID.randomUUID().toString(),
                        "rs:scope1 openid",
                        "ES256Client",
                        "http://example.com",
                        "xyz",
                        Instant.now().getEpochSecond(),
                        "abc",
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        authorizationCodeStore.save(authorizationCode);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .code(authorizationCode.code)
                        .grantType("authorization_code")
                        .redirectUri("http://example.com")
                        .authenticatedClientId("ES256Client")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        AccessTokenAssert.assertAccessToken(
                (String) response.body.get("access_token"),
                es256Key,
                subject,
                "http://rs.example.com",
                "ES256Client",
                "rs:scope1 openid",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond());
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertTrue(response.body.containsKey("refresh_token"));
        IdTokenAssert.assertIdTokenES256(
                (String) response.body.get("id_token"),
                es256Key,
                subject,
                "ES256Client",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                "abc",
                (String) response.body.get("access_token"),
                null);
    }

    @Test
    void success_oidcWithoutNonceES256() throws JOSEException, ParseException {

        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                new AuthorizationCode(
                        subject,
                        UUID.randomUUID().toString(),
                        "rs:scope1 openid",
                        "ES256Client",
                        "http://example.com",
                        "xyz",
                        Instant.now().getEpochSecond(),
                        null,
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        authorizationCodeStore.save(authorizationCode);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .code(authorizationCode.code)
                        .grantType("authorization_code")
                        .redirectUri("http://example.com")
                        .authenticatedClientId("ES256Client")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        AccessTokenAssert.assertAccessToken(
                (String) response.body.get("access_token"),
                es256Key,
                subject,
                "http://rs.example.com",
                "ES256Client",
                "rs:scope1 openid",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond());
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertTrue(response.body.containsKey("refresh_token"));
        IdTokenAssert.assertIdTokenES256(
                (String) response.body.get("id_token"),
                es256Key,
                subject,
                "ES256Client",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                null,
                (String) response.body.get("access_token"),
                null);
    }

    @Test
    void success_oidcWithoutNonceRS256() throws JOSEException, ParseException {

        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                new AuthorizationCode(
                        subject,
                        UUID.randomUUID().toString(),
                        "rs:scope1 openid",
                        "RS256Client",
                        "http://example.com",
                        "xyz",
                        Instant.now().getEpochSecond(),
                        null,
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        authorizationCodeStore.save(authorizationCode);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .code(authorizationCode.code)
                        .grantType("authorization_code")
                        .redirectUri("http://example.com")
                        .authenticatedClientId("RS256Client")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        AccessTokenAssert.assertAccessToken(
                (String) response.body.get("access_token"),
                es256Key,
                subject,
                "http://rs.example.com",
                "RS256Client",
                "rs:scope1 openid",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond());
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertTrue(response.body.containsKey("refresh_token"));
        IdTokenAssert.assertIdTokenRS256(
                (String) response.body.get("id_token"),
                rs256Key,
                subject,
                "RS256Client",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                null,
                (String) response.body.get("access_token"),
                null);
    }

    @Test
    void success_oidcWithoutNonceNone() throws JOSEException, ParseException {
        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                new AuthorizationCode(
                        subject,
                        UUID.randomUUID().toString(),
                        "rs:scope1 openid",
                        "NoneClient",
                        "http://example.com",
                        "xyz",
                        Instant.now().getEpochSecond(),
                        null,
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        authorizationCodeStore.save(authorizationCode);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .code(authorizationCode.code)
                        .grantType("authorization_code")
                        .redirectUri("http://example.com")
                        .authenticatedClientId("NoneClient")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        AccessTokenAssert.assertAccessToken(
                (String) response.body.get("access_token"),
                es256Key,
                subject,
                "http://rs.example.com",
                "NoneClient",
                "rs:scope1 openid",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond());
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertTrue(response.body.containsKey("refresh_token"));
        IdTokenAssert.assertIdTokenNone(
                (String) response.body.get("id_token"),
                subject,
                "NoneClient",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                null,
                (String) response.body.get("access_token"),
                null);
    }

    @Test
    void clientHasNotEnoughScope() throws JOSEException {
        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                new AuthorizationCode(
                        subject,
                        UUID.randomUUID().toString(),
                        "notauthorized",
                        "ES256Client",
                        "http://example.com",
                        "xyz",
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        authorizationCodeStore.save(authorizationCode);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .code(authorizationCode.code)
                        .grantType("authorization_code")
                        .redirectUri("http://example.com")
                        .authenticatedClientId("ES256Client")
                        .build();

        // exercise
        var tokenResponse = issueToken.issue(tokenRequest);

        // verify
        assertEquals(tokenResponse.status, 400);
        assertEquals("invalid_scope", tokenResponse.body.get("error"));
    }

    @Test
    void usingSameAuthorizationCode() throws JOSEException {

        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                new AuthorizationCode(
                        subject,
                        UUID.randomUUID().toString(),
                        "rs:scope1",
                        "ES256Client",
                        "http://example.com",
                        "xyz",
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        authorizationCodeStore.save(authorizationCode);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .code(authorizationCode.code)
                        .grantType("authorization_code")
                        .redirectUri("http://example.com")
                        .authenticatedClientId("ES256Client")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);

        // second time
        var response2 = issueToken.issue(tokenRequest);
        assertEquals(response.status, 200);
        assertEquals(response2.body.get("error"), "invalid_grant");
    }

    @Test
    void usingAuthorizationCodeForOtherClient() {
        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                new AuthorizationCode(
                        subject,
                        UUID.randomUUID().toString(),
                        "rs:scope1",
                        "ES256Client",
                        "http://example.com",
                        "xyz",
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        authorizationCodeStore.save(authorizationCode);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .code(authorizationCode.code)
                        .grantType("authorization_code")
                        .redirectUri("http://example.com")
                        .authenticatedClientId("other")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);
        assertEquals(response.status, 400);
        assertEquals(response.body.get("error"), "invalid_grant");
    }

    @Test
    void authorizationCodeExpired() {

        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                new AuthorizationCode(
                        subject,
                        UUID.randomUUID().toString(),
                        "rs:scope1 openid",
                        "ES256Client",
                        "http://example.com",
                        "xyz",
                        Instant.now().getEpochSecond(),
                        "abc",
                        null,
                        null,
                        Instant.now().minus(Duration.ofSeconds(10)).getEpochSecond());
        authorizationCodeStore.save(authorizationCode);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .code(authorizationCode.code)
                        .grantType("authorization_code")
                        .redirectUri("http://example.com")
                        .authenticatedClientId("ES256Client")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);
        assertEquals("invalid_grant", response.body.get("error"));
    }

    @Test
    void unmatchedRedirectUri() {
        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                new AuthorizationCode(
                        subject,
                        UUID.randomUUID().toString(),
                        "rs:scope1",
                        "ES256Client",
                        "http://example.com",
                        "xyz",
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        authorizationCodeStore.save(authorizationCode);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .code(authorizationCode.code)
                        .grantType("authorization_code")
                        .redirectUri("http://invalid.example.com")
                        .authenticatedClientId("ES256Client")
                        .build();

        // exercise
        var tokenResponse = issueToken.issue(tokenRequest);

        // verify
        assertEquals(tokenResponse.status, 400);
        assertEquals("invalid_grant", tokenResponse.body.get("error"));
    }

    @Test
    void notAuthenticatedClient() throws ParseException, JOSEException {

        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                new AuthorizationCode(
                        subject,
                        UUID.randomUUID().toString(),
                        "rs:scope1",
                        "ES256Client",
                        "http://example.com",
                        "xyz",
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        authorizationCodeStore.save(authorizationCode);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .code(authorizationCode.code)
                        .grantType("authorization_code")
                        .redirectUri("http://example.com")
                        .clientId("ES256Client")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);
        assertEquals("invalid_client", response.body.get("error"));
    }
}
