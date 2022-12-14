package org.azidp4j.token;

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
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.azidp4j.AccessTokenAssert;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.IdTokenAssert;
import org.azidp4j.authorize.authorizationcode.AuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeStore;
import org.azidp4j.client.*;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenService;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenStore;
import org.azidp4j.token.request.TokenRequest;
import org.azidp4j.util.MapUtil;
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

    private AuthorizationCodeService authorizationCodeService;

    private AccessTokenService accessTokenService;

    private IssueToken issueToken;

    private final AzIdPConfig config = Fixtures.azIdPConfig();

    private final Client es256Client =
            Fixtures.confidentialClient().idTokenSignedResponseAlg(SigningAlgorithm.ES256).build();

    private final Client rs256Client =
            Fixtures.confidentialClient().idTokenSignedResponseAlg(SigningAlgorithm.RS256).build();

    private final Client noneClient =
            Fixtures.confidentialClient().idTokenSignedResponseAlg(SigningAlgorithm.none).build();

    @BeforeEach
    void init() {
        authorizationCodeService =
                new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
        var clientStore = new InMemoryClientStore();
        clientStore.save(es256Client);
        clientStore.save(rs256Client);
        clientStore.save(noneClient);
        var scopeAudienceMapper = new SampleScopeAudienceMapper();
        accessTokenService = new InMemoryAccessTokenService(new InMemoryAccessTokenStore());
        issueToken =
                new IssueToken(
                        config,
                        authorizationCodeService,
                        accessTokenService,
                        new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks), null),
                        new InMemoryRefreshTokenService(new InMemoryRefreshTokenStore()),
                        scopeAudienceMapper,
                        null,
                        clientStore);
    }

    @Test
    void success_oauth2() {

        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                authorizationCodeService.issue(
                        subject,
                        "acr",
                        "rs:scope1",
                        null,
                        es256Client.clientId,
                        "http://example.com",
                        "xyz",
                        null,
                        null,
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        var tokenRequest =
                new TokenRequest(
                        es256Client.clientId,
                        MapUtil.ofNullable(
                                "code",
                                authorizationCode.code,
                                "grant_type",
                                "authorization_code",
                                "redirect_uri",
                                "http://example.com"));

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        AccessTokenAssert.assertAccessToken(
                accessTokenService.introspect((String) response.body.get("access_token")).get(),
                subject,
                "http://rs.example.com",
                es256Client.clientId,
                "rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600L);
        assertTrue(response.body.containsKey("refresh_token"));
    }

    @Test
    void success_oidcWithNonceES256() throws JOSEException, ParseException {

        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                authorizationCodeService.issue(
                        subject,
                        "acr",
                        "rs:scope1 openid",
                        null,
                        es256Client.clientId,
                        "http://example.com",
                        "xyz",
                        Instant.now().getEpochSecond(),
                        "abc",
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        var tokenRequest =
                new TokenRequest(
                        es256Client.clientId,
                        MapUtil.ofNullable(
                                "code",
                                authorizationCode.code,
                                "grant_type",
                                "authorization_code",
                                "redirect_uri",
                                "http://example.com"));

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        AccessTokenAssert.assertAccessToken(
                accessTokenService.introspect((String) response.body.get("access_token")).get(),
                subject,
                "http://rs.example.com",
                es256Client.clientId,
                "rs:scope1 openid",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600L);
        assertTrue(response.body.containsKey("refresh_token"));
        IdTokenAssert.assertIdTokenES256(
                (String) response.body.get("id_token"),
                es256Key,
                subject,
                es256Client.clientId,
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                "abc",
                (String) response.body.get("access_token"),
                null);
        assertEquals(
                JWSObject.parse((String) response.body.get("id_token"))
                        .getPayload()
                        .toJSONObject()
                        .get("acr"),
                "acr");
    }

    @Test
    void success_oidcWithoutNonceES256() throws JOSEException, ParseException {

        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                authorizationCodeService.issue(
                        subject,
                        "acr",
                        "rs:scope1 openid",
                        null,
                        es256Client.clientId,
                        "http://example.com",
                        "xyz",
                        Instant.now().getEpochSecond(),
                        null,
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        var tokenRequest =
                new TokenRequest(
                        es256Client.clientId,
                        MapUtil.ofNullable(
                                "code",
                                authorizationCode.code,
                                "grant_type",
                                "authorization_code",
                                "redirect_uri",
                                "http://example.com"));

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        AccessTokenAssert.assertAccessToken(
                accessTokenService.introspect((String) response.body.get("access_token")).get(),
                subject,
                "http://rs.example.com",
                es256Client.clientId,
                "rs:scope1 openid",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600L);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600L);
        assertTrue(response.body.containsKey("refresh_token"));
        IdTokenAssert.assertIdTokenES256(
                (String) response.body.get("id_token"),
                es256Key,
                subject,
                es256Client.clientId,
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
                authorizationCodeService.issue(
                        subject,
                        "acr",
                        "rs:scope1 openid",
                        null,
                        rs256Client.clientId,
                        "http://example.com",
                        "xyz",
                        Instant.now().getEpochSecond(),
                        null,
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        var tokenRequest =
                new TokenRequest(
                        rs256Client.clientId,
                        MapUtil.ofNullable(
                                "code",
                                authorizationCode.code,
                                "grant_type",
                                "authorization_code",
                                "redirect_uri",
                                "http://example.com"));

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        AccessTokenAssert.assertAccessToken(
                accessTokenService.introspect((String) response.body.get("access_token")).get(),
                subject,
                "http://rs.example.com",
                rs256Client.clientId,
                "rs:scope1 openid",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600L);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600L);
        assertTrue(response.body.containsKey("refresh_token"));
        IdTokenAssert.assertIdTokenRS256(
                (String) response.body.get("id_token"),
                rs256Key,
                subject,
                rs256Client.clientId,
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                null,
                (String) response.body.get("access_token"),
                null);
    }

    @Test
    void success_oidcWithoutNonceNone() throws ParseException {
        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                authorizationCodeService.issue(
                        subject,
                        "acr",
                        "rs:scope1 openid",
                        null,
                        noneClient.clientId,
                        "http://example.com",
                        "xyz",
                        Instant.now().getEpochSecond(),
                        null,
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        var tokenRequest =
                new TokenRequest(
                        noneClient.clientId,
                        MapUtil.ofNullable(
                                "code",
                                authorizationCode.code,
                                "grant_type",
                                "authorization_code",
                                "redirect_uri",
                                "http://example.com"));

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        AccessTokenAssert.assertAccessToken(
                accessTokenService.introspect((String) response.body.get("access_token")).get(),
                subject,
                "http://rs.example.com",
                noneClient.clientId,
                "rs:scope1 openid",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600L);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600L);
        assertTrue(response.body.containsKey("refresh_token"));
        IdTokenAssert.assertIdTokenNone(
                (String) response.body.get("id_token"),
                subject,
                noneClient.clientId,
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                null,
                (String) response.body.get("access_token"),
                null);
    }

    @Test
    void clientHasNotEnoughScope() {
        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                authorizationCodeService.issue(
                        subject,
                        "acr",
                        "notauthorized",
                        null,
                        es256Client.clientId,
                        "http://example.com",
                        "xyz",
                        null,
                        null,
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        var tokenRequest =
                new TokenRequest(
                        es256Client.clientId,
                        MapUtil.ofNullable(
                                "code",
                                authorizationCode.code,
                                "grant_type",
                                "authorization_code",
                                "redirect_uri",
                                "http://example.com"));

        // exercise
        var tokenResponse = issueToken.issue(tokenRequest);

        // verify
        assertEquals(tokenResponse.status, 400);
        assertEquals("invalid_scope", tokenResponse.body.get("error"));
    }

    @Test
    void usingSameAuthorizationCode() {

        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                authorizationCodeService.issue(
                        subject,
                        "acr",
                        "rs:scope1",
                        null,
                        es256Client.clientId,
                        "http://example.com",
                        "xyz",
                        null,
                        null,
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        var tokenRequest =
                new TokenRequest(
                        es256Client.clientId,
                        MapUtil.ofNullable(
                                "code",
                                authorizationCode.code,
                                "grant_type",
                                "authorization_code",
                                "redirect_uri",
                                "http://example.com"));

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        var at = response.body.get("access_token");
        assertNotNull(accessTokenService.introspect((String) at));

        // second time
        var response2 = issueToken.issue(tokenRequest);
        assertEquals(response2.status, 400);
        assertEquals(response2.body.get("error"), "invalid_grant");

        // using same code, access token will be revoked
        assertFalse(accessTokenService.introspect((String) at).isPresent());
    }

    @Test
    void usingAuthorizationCodeForOtherClient() {
        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                authorizationCodeService.issue(
                        subject,
                        "acr",
                        "rs:scope1",
                        null,
                        es256Client.clientId,
                        "http://example.com",
                        "xyz",
                        null,
                        null,
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        var tokenRequest =
                new TokenRequest(
                        rs256Client
                                .clientId, // authorization code by es256 but token request by rs256
                        MapUtil.ofNullable(
                                "code",
                                authorizationCode.code,
                                "grant_type",
                                "authorization_code",
                                "redirect_uri",
                                "http://example.com"));

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
                authorizationCodeService.issue(
                        subject,
                        "acr",
                        "rs:scope1 openid",
                        null,
                        es256Client.clientId,
                        "http://example.com",
                        "xyz",
                        Instant.now().getEpochSecond(),
                        "abc",
                        null,
                        null,
                        Instant.now().minus(Duration.ofSeconds(10)).getEpochSecond());
        var tokenRequest =
                new TokenRequest(
                        es256Client.clientId,
                        MapUtil.ofNullable(
                                "code",
                                authorizationCode.code,
                                "grant_type",
                                "authorization_code",
                                "redirect_uri",
                                "http://example.com"));

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
                authorizationCodeService.issue(
                        subject,
                        "acr",
                        "rs:scope1",
                        null,
                        es256Client.clientId,
                        "http://example.com",
                        "xyz",
                        null,
                        null,
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        var tokenRequest =
                new TokenRequest(
                        es256Client.clientId,
                        MapUtil.ofNullable(
                                "code",
                                authorizationCode.code,
                                "grant_type",
                                "authorization_code",
                                "redirect_uri",
                                "http://invalid.example.com"));

        // exercise
        var tokenResponse = issueToken.issue(tokenRequest);

        // verify
        assertEquals(tokenResponse.status, 400);
        assertEquals("invalid_grant", tokenResponse.body.get("error"));
    }

    @Test
    void notAuthenticatedClient() {

        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                authorizationCodeService.issue(
                        subject,
                        "acr",
                        "rs:scope1",
                        null,
                        es256Client.clientId,
                        "http://example.com",
                        "xyz",
                        null,
                        null,
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        var tokenRequest =
                new TokenRequest(
                        null,
                        MapUtil.ofNullable(
                                "code",
                                authorizationCode.code,
                                "grant_type",
                                "authorization_code",
                                "redirect_uri",
                                "http://example.com",
                                "client_id",
                                es256Client.clientId));

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);
        assertEquals("invalid_client", response.body.get("error"));
    }
}
