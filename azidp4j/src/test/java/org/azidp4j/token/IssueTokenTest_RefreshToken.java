package org.azidp4j.token;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.text.ParseException;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.azidp4j.AccessTokenAssert;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.InMemoryAuthorizationCodeStore;
import org.azidp4j.client.Client;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.accesstoken.AccessTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.refreshtoken.InMemoryRefreshTokenStore;
import org.azidp4j.token.refreshtoken.RefreshToken;
import org.junit.jupiter.api.Test;

public class IssueTokenTest_RefreshToken {

    @Test
    void success() throws JOSEException, ParseException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var accessTokenIssuer =
                new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
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
                        TokenEndpointAuthMethod.client_secret_basic));
        var refreshTokenStore = new InMemoryRefreshTokenStore();
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        new InMemoryRefreshTokenStore(),
                        null,
                        clientStore,
                        jwks);
        var refreshToken =
                new RefreshToken(
                        UUID.randomUUID().toString(),
                        "user",
                        "rs:scope1 rs:scope2",
                        "clientId",
                        Instant.now().getEpochSecond() + 3600);
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
                (String) response.body.get("access_token"),
                key,
                "user",
                "http://rs.example.com",
                "clientId",
                "rs:scope1 rs:scope2",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond());
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertTrue(response.body.containsKey("refresh_token"));
    }

    @Test
    void success_scopeShrink() throws JOSEException, ParseException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var accessTokenIssuer =
                new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
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
                        TokenEndpointAuthMethod.client_secret_basic));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        refreshTokenStore,
                        null,
                        clientStore,
                        jwks);
        var refreshToken =
                new RefreshToken(
                        UUID.randomUUID().toString(),
                        "user",
                        "rs:scope1 rs:scope2",
                        "clientId",
                        Instant.now().getEpochSecond() + 3600);
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
                (String) response.body.get("access_token"),
                key,
                "user",
                "http://rs.example.com",
                "clientId",
                "rs:scope1",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond());
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertTrue(response.body.containsKey("refresh_token"));

        var newRefreshToken = response.body.get("refresh_token");
        assertEquals(refreshTokenStore.consume(newRefreshToken.toString()).scope, "rs:scope1");
    }

    @Test
    void success_publicClient() throws JOSEException, ParseException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var accessTokenIssuer =
                new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
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
                        TokenEndpointAuthMethod.none));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        refreshTokenStore,
                        null,
                        clientStore,
                        jwks);
        var refreshToken =
                new RefreshToken(
                        UUID.randomUUID().toString(),
                        "user",
                        "rs:scope1 rs:scope2",
                        "clientId",
                        Instant.now().getEpochSecond() + 3600);
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
                (String) response.body.get("access_token"),
                key,
                "user",
                "http://rs.example.com",
                "clientId",
                "rs:scope1 rs:scope2",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond());
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertTrue(response.body.containsKey("refresh_token"));
    }

    @Test
    void error_scopeExpand() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var config = Fixtures.azIdPConfig("kid");
        var accessTokenIssuer =
                new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
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
                        TokenEndpointAuthMethod.client_secret_basic));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        refreshTokenStore,
                        null,
                        clientStore,
                        jwks);
        var refreshToken =
                new RefreshToken(
                        UUID.randomUUID().toString(),
                        "user",
                        "rs:scope1",
                        "clientId",
                        Instant.now().getEpochSecond() + 3600);
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
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var config = Fixtures.azIdPConfig("kid");
        var accessTokenIssuer =
                new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
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
                        TokenEndpointAuthMethod.client_secret_basic));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        new InMemoryRefreshTokenStore(),
                        null,
                        clientStore,
                        jwks);
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
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
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
                        key.getKeyID(),
                        key.getKeyID(),
                        3600,
                        600,
                        -1,
                        604800);
        var accessTokenIssuer =
                new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
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
                        TokenEndpointAuthMethod.client_secret_basic));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        refreshTokenStore,
                        null,
                        clientStore,
                        jwks);
        var refreshToken =
                new RefreshToken(
                        UUID.randomUUID().toString(),
                        "user",
                        "rs:scope1",
                        "clienId",
                        Instant.now().getEpochSecond() - 10);
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
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
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
                        key.getKeyID(),
                        key.getKeyID(),
                        3600,
                        600,
                        3600,
                        604800);
        var accessTokenIssuer =
                new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
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
                        TokenEndpointAuthMethod.client_secret_basic));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        new InMemoryRefreshTokenStore(),
                        null,
                        clientStore,
                        jwks);
        var refreshToken =
                new RefreshToken(
                        UUID.randomUUID().toString(),
                        "user",
                        "rs:scope1",
                        "unknown",
                        Instant.now().getEpochSecond() + 3600);
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
