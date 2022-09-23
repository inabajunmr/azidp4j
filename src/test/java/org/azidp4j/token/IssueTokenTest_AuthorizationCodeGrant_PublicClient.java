package org.azidp4j.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.text.ParseException;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.azidp4j.AccessTokenAssert;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.AuthorizationCode;
import org.azidp4j.authorize.AuthorizationCodeStore;
import org.azidp4j.authorize.InMemoryAuthorizationCodeStore;
import org.azidp4j.authorize.ResponseType;
import org.azidp4j.client.Client;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.accesstoken.AccessTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.refreshtoken.RefreshTokenIssuer;
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

    private AuthorizationCodeStore authorizationCodeStore;

    private IssueToken issueToken;

    private final AzIdPConfig config =
            new AzIdPConfig("as.example.com", key.getKeyID(), key.getKeyID(), 3600, 604800, 3600);

    @BeforeEach
    void init() {
        authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.authorization_code),
                        Set.of(ResponseType.code),
                        "openid rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.none));
        issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper()),
                        new IDTokenIssuer(config, jwks),
                        new RefreshTokenIssuer(config, jwks, new SampleScopeAudienceMapper()),
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
                        "clientId",
                        "http://example.com",
                        "xyz");
        authorizationCodeStore.save(authorizationCode);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .code(authorizationCode.code)
                        .grantType("authorization_code")
                        .redirectUri("http://example.com")
                        .clientId("clientId")
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        AccessTokenAssert.assertAccessToken(
                (String) response.body.get("access_token"),
                key,
                subject,
                "http://rs.example.com",
                "clientId",
                "rs:scope1",
                "as.example.com",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond());
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertTrue(response.body.containsKey("refresh_token"));
    }
}
