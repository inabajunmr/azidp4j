package org.azidp4j.token;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.azidp4j.AccessTokenAssert;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeStore;
import org.azidp4j.client.*;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.refreshtoken.RefreshToken;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenService;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenStore;
import org.azidp4j.token.request.TokenRequest;
import org.azidp4j.util.MapUtil;
import org.junit.jupiter.api.Test;

public class IssueTokenTest_RefreshToken {
    private final InMemoryRefreshTokenStore refreshTokenStore;

    private final IssueToken issueToken;

    private final InMemoryAccessTokenStore accessTokenStore;

    public IssueTokenTest_RefreshToken() throws JOSEException {
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeService =
                new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
        var config = Fixtures.azIdPConfig();
        this.accessTokenStore = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks));
        var clientStore = new InMemoryClientStore();
        clientStore.save(Fixtures.confidentialClient());
        clientStore.save(Fixtures.publicClient());
        this.refreshTokenStore = new InMemoryRefreshTokenStore();
        var scopeAudienceMapper = new SampleScopeAudienceMapper();
        this.issueToken =
                new IssueToken(
                        config,
                        authorizationCodeService,
                        new InMemoryAccessTokenService(accessTokenStore),
                        idTokenIssuer,
                        new InMemoryRefreshTokenService(new InMemoryRefreshTokenStore()),
                        scopeAudienceMapper,
                        null,
                        clientStore);
    }

    @Test
    void success() {

        // setup
        var refreshToken =
                new RefreshToken(
                        UUID.randomUUID().toString(),
                        "user",
                        "rs:scope1 rs:scope2",
                        "confidential",
                        Set.of("scope"),
                        Instant.now().getEpochSecond() + 3600,
                        Instant.now().getEpochSecond());
        refreshTokenStore.save(refreshToken);
        var tokenRequest =
                new TokenRequest(
                        "confidential",
                        MapUtil.ofNullable(
                                "grant_type",
                                "refresh_token",
                                "scope",
                                "rs:scope1 rs:scope2",
                                "refresh_token",
                                refreshToken.token));

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find((String) response.body.get("access_token")).get(),
                "user",
                "http://rs.example.com",
                "confidential",
                "rs:scope1 rs:scope2",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600L);
        assertTrue(response.body.containsKey("refresh_token"));
    }

    @Test
    void success_scopeShrink() {

        // setup
        var refreshToken =
                new RefreshToken(
                        UUID.randomUUID().toString(),
                        "user",
                        "rs:scope1 rs:scope2",
                        "confidential",
                        Set.of("rs"),
                        Instant.now().getEpochSecond() + 3600,
                        Instant.now().getEpochSecond());
        refreshTokenStore.save(refreshToken);
        var tokenRequest =
                new TokenRequest(
                        "confidential",
                        MapUtil.ofNullable(
                                "grant_type",
                                "refresh_token",
                                "scope",
                                "rs:scope1",
                                "refresh_token",
                                refreshToken.token));

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find((String) response.body.get("access_token")).get(),
                "user",
                "http://rs.example.com",
                "confidential",
                "rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600L);
        assertTrue(response.body.containsKey("refresh_token"));

        var newRefreshToken = response.body.get("refresh_token");
        assertEquals(
                refreshTokenStore.consume(newRefreshToken.toString()).get().scope, "rs:scope1");
    }

    @Test
    void success_publicClient() {

        // setup
        var refreshToken =
                new RefreshToken(
                        UUID.randomUUID().toString(),
                        "user",
                        "rs:scope1 rs:scope2",
                        "public",
                        Set.of("rs"),
                        Instant.now().getEpochSecond() + 3600,
                        Instant.now().getEpochSecond());
        refreshTokenStore.save(refreshToken);
        var tokenRequest =
                new TokenRequest(
                        null,
                        MapUtil.ofNullable(
                                "grant_type",
                                "refresh_token",
                                "scope",
                                "rs:scope1 rs:scope2",
                                "refresh_token",
                                refreshToken.token,
                                "client_id",
                                "public"));
        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find((String) response.body.get("access_token")).get(),
                "user",
                "http://rs.example.com",
                "public",
                "rs:scope1 rs:scope2",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600L);
        assertTrue(response.body.containsKey("refresh_token"));
    }

    @Test
    void error_scopeExpand() {

        // setup
        var refreshToken =
                new RefreshToken(
                        UUID.randomUUID().toString(),
                        "user",
                        "rs:scope1",
                        "confidential",
                        Set.of("rs"),
                        Instant.now().getEpochSecond() + 3600,
                        Instant.now().getEpochSecond());
        refreshTokenStore.save(refreshToken);
        var tokenRequest =
                new TokenRequest(
                        "confidential",
                        MapUtil.ofNullable(
                                "grant_type",
                                "refresh_token",
                                "scope",
                                "rs:scope1 rs:scope2",
                                "refresh_token",
                                refreshToken.token));

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);

        // access token
        assertEquals("invalid_scope", response.body.get("error"));
    }

    @Test
    void error_refreshTokenIsNotFound() {

        // setup
        var tokenRequest =
                new TokenRequest(
                        "confidential",
                        MapUtil.ofNullable(
                                "grant_type",
                                "refresh_token",
                                "scope",
                                "rs:scope1 rs:scope2",
                                "refresh_token",
                                "invalid"));

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);

        // access token
        assertEquals("invalid_grant", response.body.get("error"));
    }

    @Test
    void error_expiredRefreshToken() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeService =
                new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
        var config =
                new AzIdPConfig(
                        "http://localhost:8080",
                        Set.of("openid", "scope1", "scope2", "default"),
                        Set.of("openid", "scope1"),
                        Set.of(TokenEndpointAuthMethod.client_secret_basic),
                        null,
                        Set.of(TokenEndpointAuthMethod.client_secret_basic),
                        null,
                        Set.of(TokenEndpointAuthMethod.client_secret_basic),
                        null,
                        Set.of(GrantType.refresh_token),
                        Set.of(),
                        Set.of(),
                        Set.of(SigningAlgorithm.ES256),
                        Duration.ofSeconds(3600),
                        Duration.ofSeconds(600),
                        Duration.ofSeconds(-1), // always issuing expired
                        Duration.ofSeconds(604800));
        var accessTokenStore = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks));
        var refreshTokenStore = new InMemoryRefreshTokenStore();
        var clientStore = new InMemoryClientStore();
        clientStore.save(Fixtures.confidentialClient());
        var scopeAudienceMapper = new SampleScopeAudienceMapper();
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeService,
                        new InMemoryAccessTokenService(accessTokenStore),
                        idTokenIssuer,
                        new InMemoryRefreshTokenService(new InMemoryRefreshTokenStore()),
                        scopeAudienceMapper,
                        null,
                        clientStore);
        var refreshToken =
                new RefreshToken(
                        UUID.randomUUID().toString(),
                        "user",
                        "rs:scope1",
                        "confidential",
                        Set.of("rs"),
                        Instant.now().getEpochSecond() - 10,
                        Instant.now().getEpochSecond());
        refreshTokenStore.save(refreshToken);
        var tokenRequest =
                new TokenRequest(
                        "confidential",
                        MapUtil.ofNullable(
                                "grant_type",
                                "refresh_token",
                                "scope",
                                "rs:scope1",
                                "refresh_token",
                                refreshToken.token));
        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);
        assertEquals("invalid_grant", response.body.get("error"));
    }

    @Test
    void error_authenticatedClientUnmatched() {

        // setup
        var refreshToken =
                new RefreshToken(
                        UUID.randomUUID().toString(),
                        "user",
                        "rs:scope1",
                        "unknown",
                        Set.of("rs"),
                        Instant.now().getEpochSecond() + 3600,
                        Instant.now().getEpochSecond());
        refreshTokenStore.save(refreshToken);
        var tokenRequest =
                new TokenRequest(
                        "confidential",
                        MapUtil.ofNullable(
                                "grant_type",
                                "refresh_token",
                                "scope",
                                "rs:scope1",
                                "refresh_token",
                                refreshToken.token));

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);
        assertEquals("invalid_grant", response.body.get("error"));
    }
}
