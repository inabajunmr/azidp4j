package org.azidp4j.token;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.InMemoryAuthorizationCodeStore;
import org.azidp4j.client.Client;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.accesstoken.AccessTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.refreshtoken.RefreshTokenIssuer;
import org.junit.jupiter.api.Test;

public class IssueTokenTest_RefreshToken {

    @Test
    void success() throws JOSEException, ParseException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var config =
                new AzIdPConfig(
                        "as.example.com", key.getKeyID(), key.getKeyID(), 3600, 604800, 3600);
        var accessTokenIssuer =
                new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var refreshTokenIssuer =
                new RefreshTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.refresh_token),
                        Set.of(),
                        "rs:scope1 rs:scope2"));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        refreshTokenIssuer,
                        null,
                        clientStore,
                        jwks);
        var rt = refreshTokenIssuer.issue("user", "clientId", "rs:scope1 rs:scope2");
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("refresh_token")
                        .scope("rs:scope1 rs:scope2")
                        .refreshToken(rt.serialize())
                        .authenticatedClientId("clientId")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        var accessToken = response.body.get("access_token");
        var parsedAccessToken = JWSObject.parse((String) accessToken);
        // verify signature
        assertTrue(parsedAccessToken.verify(new ECDSAVerifier(key)));
        assertEquals(parsedAccessToken.getHeader().getAlgorithm(), JWSAlgorithm.ES256);
        assertEquals(parsedAccessToken.getHeader().getType().getType(), "at+JWT");
        // verify claims
        var payload = parsedAccessToken.getPayload().toJSONObject();
        assertEquals(payload.get("sub"), "user");
        assertEquals(payload.get("aud"), List.of("http://rs.example.com"));
        assertEquals(payload.get("client_id"), "clientId");
        assertEquals(payload.get("scope"), "rs:scope1 rs:scope2");
        assertNotNull(payload.get("jti"));
        assertEquals(payload.get("iss"), "as.example.com");
        assertTrue((long) payload.get("exp") > Instant.now().getEpochSecond() + 3590);
        assertTrue((long) payload.get("exp") < Instant.now().getEpochSecond() + 3610);
        assertTrue((long) payload.get("iat") > Instant.now().getEpochSecond() - 10);
        assertTrue((long) payload.get("iat") < Instant.now().getEpochSecond() + 10);
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
        var config =
                new AzIdPConfig(
                        "as.example.com", key.getKeyID(), key.getKeyID(), 3600, 604800, 3600);
        var accessTokenIssuer =
                new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var refreshTokenIssuer =
                new RefreshTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.refresh_token),
                        Set.of(),
                        "rs:scope1 rs:scope2"));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        refreshTokenIssuer,
                        null,
                        clientStore,
                        jwks);
        var rt = refreshTokenIssuer.issue("user", "clientId", "rs:scope1 rs:scope2");
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("refresh_token")
                        .scope("rs:scope1")
                        .refreshToken(rt.serialize())
                        .authenticatedClientId("clientId")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        var accessToken = response.body.get("access_token");
        var parsedAccessToken = JWSObject.parse((String) accessToken);
        // verify signature
        assertTrue(parsedAccessToken.verify(new ECDSAVerifier(key)));
        assertEquals(parsedAccessToken.getHeader().getAlgorithm(), JWSAlgorithm.ES256);
        assertEquals(parsedAccessToken.getHeader().getType().getType(), "at+JWT");
        // verify claims
        var payload = parsedAccessToken.getPayload().toJSONObject();
        assertEquals(payload.get("sub"), "user");
        assertEquals(payload.get("aud"), List.of("http://rs.example.com"));
        assertEquals(payload.get("client_id"), "clientId");
        assertEquals(payload.get("scope"), "rs:scope1");
        assertNotNull(payload.get("jti"));
        assertEquals(payload.get("iss"), "as.example.com");
        assertTrue((long) payload.get("exp") > Instant.now().getEpochSecond() + 3590);
        assertTrue((long) payload.get("exp") < Instant.now().getEpochSecond() + 3610);
        assertTrue((long) payload.get("iat") > Instant.now().getEpochSecond() - 10);
        assertTrue((long) payload.get("iat") < Instant.now().getEpochSecond() + 10);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertTrue(response.body.containsKey("refresh_token"));

        var refreshToken = response.body.get("refresh_token");
        var parsedRefreshToken = JWSObject.parse((String) refreshToken).getPayload().toJSONObject();
        assertEquals(parsedRefreshToken.get("scope"), "rs:scope1");
    }

    @Test
    void error_scopeExpand() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var config =
                new AzIdPConfig(
                        "as.example.com", key.getKeyID(), key.getKeyID(), 3600, 604800, 3600);
        var accessTokenIssuer =
                new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var refreshTokenIssuer =
                new RefreshTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.refresh_token),
                        Set.of(),
                        "rs:scope1 rs:scope2"));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        refreshTokenIssuer,
                        null,
                        clientStore,
                        jwks);
        var rt = refreshTokenIssuer.issue("user", "clientId", "rs:scope1");
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("refresh_token")
                        .scope("rs:scope1 rs:scope2")
                        .refreshToken(rt.serialize())
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
    void error_refreshTokenIsNotJWT() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var config =
                new AzIdPConfig(
                        "as.example.com", key.getKeyID(), key.getKeyID(), 3600, 604800, 3600);
        var accessTokenIssuer =
                new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var refreshTokenIssuer =
                new RefreshTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.refresh_token),
                        Set.of(),
                        "rs:scope1 rs:scope2"));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        refreshTokenIssuer,
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
    void error_refreshTokenIsValidSignedJWT() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var config =
                new AzIdPConfig(
                        "as.example.com", key.getKeyID(), key.getKeyID(), 3600, 604800, 3600);
        var accessTokenIssuer =
                new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var key2 = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks2 = new JWKSet(key2);
        var refreshTokenIssuer =
                new RefreshTokenIssuer(
                        new AzIdPConfig(
                                "as.example.com",
                                key2.getKeyID(),
                                key2.getKeyID(),
                                3600,
                                604800,
                                604800),
                        jwks2,
                        new SampleScopeAudienceMapper());
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.refresh_token),
                        Set.of(),
                        "rs:scope1 rs:scope2"));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        refreshTokenIssuer,
                        null,
                        clientStore,
                        jwks);
        var rt = refreshTokenIssuer.issue("user", "clientId", "rs:scope1");
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("refresh_token")
                        .scope("rs:scope1 rs:scope2")
                        .refreshToken(rt.serialize())
                        .authenticatedClientId("clientId")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);
        assertEquals("invalid_grant", response.body.get("error"));
    }

    @Test
    void error_invalidIssuer() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var config =
                new AzIdPConfig(
                        "as.example.com", key.getKeyID(), key.getKeyID(), 3600, 604800, 3600);
        var accessTokenIssuer =
                new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var refreshTokenIssuer =
                new RefreshTokenIssuer(
                        new AzIdPConfig(
                                "unknown.example.com",
                                key.getKeyID(),
                                key.getKeyID(),
                                3600,
                                604800,
                                604800),
                        jwks,
                        new SampleScopeAudienceMapper());
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.refresh_token),
                        Set.of(),
                        "rs:scope1 rs:scope2"));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        refreshTokenIssuer,
                        null,
                        clientStore,
                        jwks);
        var rt = refreshTokenIssuer.issue("user", "clientId", "rs:scope1");
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("refresh_token")
                        .scope("rs:scope1 rs:scope2")
                        .refreshToken(rt.serialize())
                        .authenticatedClientId("clientId")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);
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
                new AzIdPConfig("as.example.com", key.getKeyID(), key.getKeyID(), 3600, -1, 604800);
        var accessTokenIssuer =
                new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var refreshTokenIssuer =
                new RefreshTokenIssuer(config, jwks, new SampleScopeAudienceMapper());
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.refresh_token),
                        Set.of(),
                        "rs:scope1 rs:scope2"));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        refreshTokenIssuer,
                        null,
                        clientStore,
                        jwks);
        var rt = refreshTokenIssuer.issue("user", "clientId", "rs:scope1");
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("refresh_token")
                        .scope("rs:scope1")
                        .refreshToken(rt.serialize())
                        .authenticatedClientId("clientId")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);
        assertEquals("invalid_grant", response.body.get("error"));
    }
}
