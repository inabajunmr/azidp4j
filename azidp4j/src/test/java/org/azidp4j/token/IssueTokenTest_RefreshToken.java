package org.azidp4j.token;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
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
import org.azidp4j.token.request.InternalTokenRequest;
import org.junit.jupiter.api.Test;

public class IssueTokenTest_RefreshToken {

    @Test
    void success() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeService =
                new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.refresh_token),
                        Set.of(),
                        "rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        SigningAlgorithm.ES256));
        var refreshTokenStore = new InMemoryRefreshTokenStore();
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
                        "rs:scope1 rs:scope2",
                        "clientId",
                        Set.of("scope"),
                        Instant.now().getEpochSecond() + 3600,
                        Instant.now().getEpochSecond());
        refreshTokenStore.save(refreshToken);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("refresh_token")
                        .scope("rs:scope1 rs:scope2")
                        .refreshToken(refreshToken.token)
                        .authenticatedClientId("clientId")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find((String) response.body.get("access_token")).get(),
                "user",
                "http://rs.example.com",
                "clientId",
                "rs:scope1 rs:scope2",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertTrue(response.body.containsKey("refresh_token"));
    }

    @Test
    void success_scopeShrink() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeService =
                new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var refreshTokenStore = new InMemoryRefreshTokenStore();
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.refresh_token),
                        Set.of(),
                        "rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        SigningAlgorithm.ES256));
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
                        "rs:scope1 rs:scope2",
                        "clientId",
                        Set.of("rs"),
                        Instant.now().getEpochSecond() + 3600,
                        Instant.now().getEpochSecond());
        refreshTokenStore.save(refreshToken);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("refresh_token")
                        .scope("rs:scope1")
                        .refreshToken(refreshToken.token)
                        .authenticatedClientId("clientId")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find((String) response.body.get("access_token")).get(),
                "user",
                "http://rs.example.com",
                "clientId",
                "rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertTrue(response.body.containsKey("refresh_token"));

        var newRefreshToken = response.body.get("refresh_token");
        assertEquals(
                refreshTokenStore.consume(newRefreshToken.toString()).get().scope, "rs:scope1");
    }

    @Test
    void success_publicClient() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeService =
                new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var refreshTokenStore = new InMemoryRefreshTokenStore();
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.refresh_token),
                        Set.of(),
                        "rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.none,
                        SigningAlgorithm.ES256));
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
                        "rs:scope1 rs:scope2",
                        "clientId",
                        Set.of("rs"),
                        Instant.now().getEpochSecond() + 3600,
                        Instant.now().getEpochSecond());
        refreshTokenStore.save(refreshToken);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("refresh_token")
                        .scope("rs:scope1 rs:scope2")
                        .refreshToken(refreshToken.token)
                        .clientId("clientId")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find((String) response.body.get("access_token")).get(),
                "user",
                "http://rs.example.com",
                "clientId",
                "rs:scope1 rs:scope2",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertTrue(response.body.containsKey("refresh_token"));
    }

    @Test
    void error_scopeExpand() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeService =
                new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
        var config = Fixtures.azIdPConfig("kid");
        var accessTokenStore = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var refreshTokenStore = new InMemoryRefreshTokenStore();
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.refresh_token),
                        Set.of(),
                        "rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        SigningAlgorithm.ES256));
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
                        "clientId",
                        Set.of("rs"),
                        Instant.now().getEpochSecond() + 3600,
                        Instant.now().getEpochSecond());
        refreshTokenStore.save(refreshToken);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("refresh_token")
                        .scope("rs:scope1 rs:scope2")
                        .refreshToken(refreshToken.token)
                        .authenticatedClientId("clientId")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);

        // access token
        assertEquals("invalid_scope", response.body.get("error"));
    }

    @Test
    void error_refreshTokenIsNotFound() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeService =
                new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
        var config = Fixtures.azIdPConfig("kid");
        var accessTokenStore = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.refresh_token),
                        Set.of(),
                        "rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        SigningAlgorithm.ES256));
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
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("refresh_token")
                        .scope("rs:scope1 rs:scope2")
                        .refreshToken("invalid")
                        .authenticatedClientId("clientId")
                        .build();

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
        // always issuing expired
        var config =
                new AzIdPConfig(
                        "http://localhost:8080",
                        "http://localhost:8080/authorize",
                        "http://localhost:8080/token",
                        "http://localhost:8080/.well-known/jwks.json",
                        "http://localhost:8080/client",
                        "http://localhost:8080/client/{CLIENT_ID}",
                        "http://localhost:8080/userinfo",
                        Set.of("openid", "scope1", "scope2", "default"),
                        Set.of("openid", "scope1"),
                        key.getKeyID(),
                        3600,
                        600,
                        -1,
                        604800);
        var accessTokenStore = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var refreshTokenStore = new InMemoryRefreshTokenStore();
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.refresh_token),
                        Set.of(),
                        "rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        SigningAlgorithm.ES256));
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
                        "clientId",
                        Set.of("rs"),
                        Instant.now().getEpochSecond() - 10,
                        Instant.now().getEpochSecond());
        refreshTokenStore.save(refreshToken);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("refresh_token")
                        .scope("rs:scope1")
                        .refreshToken(refreshToken.token)
                        .authenticatedClientId("clientId")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);
        assertEquals("invalid_grant", response.body.get("error"));
    }

    @Test
    void error_authenticatedClientUnmatched() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeService =
                new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
        // always issuing expired
        var config =
                new AzIdPConfig(
                        "http://localhost:8080",
                        "http://localhost:8080/authorize",
                        "http://localhost:8080/token",
                        "http://localhost:8080/.well-known/jwks.json",
                        "http://localhost:8080/client",
                        "http://localhost:8080/client/{CLIENT_ID}",
                        "http://localhost:8080/userinfo",
                        Set.of("openid", "scope1", "scope2", "default"),
                        Set.of("openid", "scope1"),
                        key.getKeyID(),
                        3600,
                        600,
                        3600,
                        604800);
        var accessTokenStore = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.refresh_token),
                        Set.of(),
                        "rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        SigningAlgorithm.ES256));
        var refreshTokenStore = new InMemoryRefreshTokenStore();
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
                        "unknown",
                        Set.of("rs"),
                        Instant.now().getEpochSecond() + 3600,
                        Instant.now().getEpochSecond());
        refreshTokenStore.save(refreshToken);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("refresh_token")
                        .scope("rs:scope1")
                        .refreshToken(refreshToken.token)
                        .authenticatedClientId("clientId")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);
        assertEquals("invalid_grant", response.body.get("error"));
    }

    // TODO id_token?
}
