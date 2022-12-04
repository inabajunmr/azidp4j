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
import org.azidp4j.token.request.TokenRequest;
import org.azidp4j.util.MapUtil;
import org.junit.jupiter.api.Test;

class IssueTokenTest_ResourceOwnerPasswordCredentialsGrant {

    private final IssueToken issueToken;

    private final InMemoryAccessTokenStore accessTokenStore;

    IssueTokenTest_ResourceOwnerPasswordCredentialsGrant() throws JOSEException {
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeService =
                new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
        var config = Fixtures.azIdPConfig();
        this.accessTokenStore = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks));
        var userPasswordVerifier =
                new UserPasswordVerifier() {
                    @Override
                    public boolean verify(String username, String password) {
                        return true;
                    }
                };
        var clientStore = new InMemoryClientStore();
        clientStore.save(Fixtures.confidentialClient());
        clientStore.save(Fixtures.publicClient());
        var scopeAudienceMapper = new SampleScopeAudienceMapper();
        this.issueToken =
                new IssueToken(
                        config,
                        authorizationCodeService,
                        new InMemoryAccessTokenService(accessTokenStore),
                        idTokenIssuer,
                        new InMemoryRefreshTokenService(new InMemoryRefreshTokenStore()),
                        scopeAudienceMapper,
                        userPasswordVerifier,
                        clientStore);
    }

    @Test
    void success() {

        // setup
        var tokenRequest =
                new TokenRequest(
                        "confidential",
                        MapUtil.ofNullable(
                                "grant_type",
                                "password",
                                "username",
                                "username",
                                "password",
                                "password",
                                "scope",
                                "rs:scope1"));

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find((String) response.body.get("access_token")).get(),
                "username",
                "http://rs.example.com",
                "confidential",
                "rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600L);
        assertTrue(response.body.containsKey("refresh_token"));
    }

    @Test
    void success_publicClient() {

        // setup
        var tokenRequest =
                new TokenRequest(
                        null,
                        MapUtil.ofNullable(
                                "grant_type",
                                "password",
                                "username",
                                "username",
                                "password",
                                "password",
                                "scope",
                                "rs:scope1",
                                "client_id",
                                "public"));
        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find((String) response.body.get("access_token")).get(),
                "username",
                "http://rs.example.com",
                "public",
                "rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600L);
        assertTrue(response.body.containsKey("refresh_token"));
    }

    @Test
    void userAuthenticationFailed() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeService =
                new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
        var config = Fixtures.azIdPConfig();
        var accessTokenStore = new InMemoryAccessTokenStore();
        var idTokenIssuer = new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks));
        var userPasswordVerifier =
                new UserPasswordVerifier() {
                    @Override
                    public boolean verify(String username, String password) {
                        return false;
                    }
                };
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
                        userPasswordVerifier,
                        clientStore);
        var tokenRequest =
                new TokenRequest(
                        "confidential",
                        MapUtil.ofNullable(
                                "grant_type",
                                "password",
                                "username",
                                "username",
                                "password",
                                "password",
                                "scope",
                                "rs:scope1"));

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);
        // access token
        var error = response.body.get("error");
        assertEquals(error, "invalid_grant");
    }

    @Test
    void clientHasNotEnoughScope() {

        // setup
        var tokenRequest =
                new TokenRequest(
                        "confidential",
                        MapUtil.ofNullable(
                                "grant_type",
                                "password",
                                "username",
                                "username",
                                "password",
                                "password",
                                "scope",
                                "unauthorized"));
        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 400);
        assertEquals(response.body.get("error"), "invalid_scope");
    }
}
