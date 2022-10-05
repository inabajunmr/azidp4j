package org.azidp4j.token;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.text.ParseException;
import java.time.Instant;
import java.util.Set;
import org.azidp4j.AccessTokenAssert;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.InMemoryAuthorizationCodeStore;
import org.azidp4j.client.Client;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.client.SigningAlgorithm;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.accesstoken.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.refreshtoken.InMemoryRefreshTokenStore;
import org.junit.jupiter.api.Test;

class IssueTokenTest_ResourceOwnerPasswordCredentialsGrant {

    @Test
    void success() throws JOSEException, ParseException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var userPasswordVerifier =
                new UserPasswordVerifier() {
                    @Override
                    public boolean verify(String username, String password) {
                        return true;
                    }
                };
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.password),
                        Set.of(),
                        "rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        Set.of(SigningAlgorithm.ES256)));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenStore,
                        idTokenIssuer,
                        new InMemoryRefreshTokenStore(),
                        new SampleScopeAudienceMapper(),
                        userPasswordVerifier,
                        clientStore,
                        jwks);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("password")
                        .username("username")
                        .password("password")
                        .authenticatedClientId("clientId")
                        .scope("rs:scope1")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find((String) response.body.get("access_token")),
                "username",
                "http://rs.example.com",
                "clientId",
                "rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertTrue(response.body.containsKey("refresh_token"));
    }

    @Test
    void success_publicClient() throws JOSEException, ParseException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var accessTokenStore = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var userPasswordVerifier =
                new UserPasswordVerifier() {
                    @Override
                    public boolean verify(String username, String password) {
                        return true;
                    }
                };
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.password),
                        Set.of(),
                        "rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.none,
                        Set.of(SigningAlgorithm.ES256)));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenStore,
                        idTokenIssuer,
                        new InMemoryRefreshTokenStore(),
                        new SampleScopeAudienceMapper(),
                        userPasswordVerifier,
                        clientStore,
                        jwks);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("password")
                        .username("username")
                        .password("password")
                        .clientId("clientId")
                        .scope("rs:scope1")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find((String) response.body.get("access_token")),
                "username",
                "http://rs.example.com",
                "clientId",
                "rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertTrue(response.body.containsKey("refresh_token"));
    }

    @Test
    void userAuthenticationFailed() throws JOSEException, ParseException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var accessTokenIssuer = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var userPasswordVerifier =
                new UserPasswordVerifier() {
                    @Override
                    public boolean verify(String username, String password) {
                        return false;
                    }
                };
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.password),
                        Set.of(),
                        "rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        Set.of(SigningAlgorithm.ES256)));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        new InMemoryRefreshTokenStore(),
                        new SampleScopeAudienceMapper(),
                        userPasswordVerifier,
                        clientStore,
                        jwks);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("password")
                        .username("username")
                        .password("password")
                        .authenticatedClientId("clientId")
                        .scope("rs:scope1")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);
        // access token
        var error = response.body.get("error");
        assertEquals(error, "invalid_grant");
    }

    @Test
    void clientHasNotEnoughScope() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var accessTokenIssuer = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks);
        var userPasswordVerifier =
                new UserPasswordVerifier() {
                    @Override
                    public boolean verify(String username, String password) {
                        return true;
                    }
                };
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.password),
                        Set.of(),
                        "rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        Set.of(SigningAlgorithm.ES256)));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenIssuer,
                        idTokenIssuer,
                        new InMemoryRefreshTokenStore(),
                        new SampleScopeAudienceMapper(),
                        userPasswordVerifier,
                        clientStore,
                        jwks);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("password")
                        .username("username")
                        .password("password")
                        .authenticatedClientId("clientId")
                        .scope("unauthorized")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);
        assertEquals(response.body.get("error"), "invalid_scope");
    }
}
