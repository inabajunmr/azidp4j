package org.azidp4j.token;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.time.Instant;
import org.azidp4j.AccessTokenAssert;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeStore;
import org.azidp4j.client.*;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenService;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenStore;
import org.azidp4j.token.request.InternalTokenRequest;
import org.junit.jupiter.api.Test;

class IssueTokenTest_ClientCredentialsGrant {

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
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("client_credentials")
                        .authenticatedClientId("confidential")
                        .scope("rs:scope1")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find((String) response.body.get("access_token")).get(),
                "confidential",
                "http://rs.example.com",
                "confidential",
                "rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertFalse(response.body.containsKey("refresh_token"));
    }

    @Test
    void clientHasNotEnoughScope() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeService =
                new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
        var config = Fixtures.azIdPConfig("kid");
        var accessTokenStore = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
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
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("client_credentials")
                        .authenticatedClientId("confidential")
                        .scope("rs:unauthorized")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);
        assertEquals(response.body.get("error"), "invalid_scope");
    }

    @Test
    void notAuthenticatedClient() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeService =
                new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
        var config = Fixtures.azIdPConfig("kid");
        var accessTokenStore = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
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
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("client_credentials")
                        .clientId("confidential")
                        .scope("rs:unauthorized")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);
        assertEquals(response.body.get("error"), "invalid_client");
    }

    @Test
    void publicClient() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeService =
                new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
        var config = Fixtures.azIdPConfig("kid");
        var accessTokenStore = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var clientStore = new InMemoryClientStore();
        clientStore.save(Fixtures.publicClient());
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
                        .grantType("client_credentials")
                        .authenticatedClientId("public")
                        .scope("rs:scope1")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);
        assertEquals(response.body.get("error"), "invalid_client");
    }
}
