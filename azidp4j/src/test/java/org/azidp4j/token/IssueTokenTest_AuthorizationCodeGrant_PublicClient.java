package org.azidp4j.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.time.Instant;
import java.util.UUID;
import org.azidp4j.AccessTokenAssert;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.authorizationcode.AuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeStore;
import org.azidp4j.authorize.request.CodeChallengeMethod;
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

class IssueTokenTest_AuthorizationCodeGrant_PublicClient {

    private final ECKey key;

    {
        try {
            key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private final JWKSet jwks = new JWKSet(key);

    private AuthorizationCodeService authorizationCodeService;

    private AccessTokenService accessTokenService;

    private IssueToken issueToken;

    private final AzIdPConfig config = Fixtures.azIdPConfig();

    private final Client client = Fixtures.publicClient();

    @BeforeEach
    void init() {
        authorizationCodeService =
                new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
        var clientStore = new InMemoryClientStore();
        clientStore.save(client);
        var scopeAudienceMapper = new SampleScopeAudienceMapper();
        accessTokenService = new InMemoryAccessTokenService(new InMemoryAccessTokenStore());
        issueToken =
                new IssueToken(
                        config,
                        authorizationCodeService,
                        accessTokenService,
                        new IDTokenIssuer(config, jwks, (alg) -> "123", null),
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
                        "rs:scope1",
                        null,
                        client.clientId,
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
                                client.clientId));
        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        AccessTokenAssert.assertAccessToken(
                accessTokenService.introspect((String) response.body.get("access_token")).get(),
                subject,
                "http://rs.example.com",
                client.clientId,
                "rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600L);
        assertTrue(response.body.containsKey("refresh_token"));
    }

    @Test
    void success_pkce_plain() {

        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                authorizationCodeService.issue(
                        subject,
                        "rs:scope1",
                        null,
                        client.clientId,
                        "http://example.com",
                        "xyz",
                        null,
                        null,
                        "plain",
                        CodeChallengeMethod.PLAIN,
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
                                client.clientId,
                                "code_verifier",
                                "plain"));

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        AccessTokenAssert.assertAccessToken(
                accessTokenService.introspect((String) response.body.get("access_token")).get(),
                subject,
                "http://rs.example.com",
                client.clientId,
                "rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600L);
        assertTrue(response.body.containsKey("refresh_token"));
    }

    @Test
    void success_pkce_s256() {

        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                authorizationCodeService.issue(
                        subject,
                        "rs:scope1",
                        null,
                        client.clientId,
                        "http://example.com",
                        "xyz",
                        null,
                        null,
                        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        CodeChallengeMethod.S256,
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
                                client.clientId,
                                "code_verifier",
                                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        AccessTokenAssert.assertAccessToken(
                accessTokenService.introspect((String) response.body.get("access_token")).get(),
                subject,
                "http://rs.example.com",
                client.clientId,
                "rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600L);
        assertTrue(response.body.containsKey("refresh_token"));
    }

    @Test
    void error_pkce_plain() {

        // setup
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                authorizationCodeService.issue(
                        subject,
                        "rs:scope1",
                        null,
                        client.clientId,
                        "http://example.com",
                        "xyz",
                        null,
                        null,
                        "plain",
                        CodeChallengeMethod.PLAIN,
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
                                client.clientId,
                                "code_verifier",
                                "invalid"));

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.body.get("error"), "invalid_grant");
    }
}
