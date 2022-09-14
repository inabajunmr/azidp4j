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
import java.util.UUID;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.AuthorizationCode;
import org.azidp4j.authorize.InMemoryAuthorizationCodeStore;
import org.azidp4j.authorize.ResponseType;
import org.azidp4j.client.Client;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.accesstoken.AccessTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.refreshtoken.RefreshTokenIssuer;
import org.junit.jupiter.api.Test;

class IssueTokenTest_AuthorizationCodeGrant {

    @Test
    void success_oauth2() throws JOSEException, ParseException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                new AuthorizationCode(
                        subject, UUID.randomUUID().toString(), "rs:scope1", "clientId", "xyz");
        authorizationCodeStore.save(authorizationCode);
        var config =
                new AzIdPConfig(
                        "as.example.com", key.getKeyID(), key.getKeyID(), 3600, 604800, 3600);
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.authorization_code),
                        Set.of(ResponseType.code),
                        "rs:scope1 rs:scope2"));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper()),
                        new IDTokenIssuer(config, jwks),
                        new RefreshTokenIssuer(config, jwks, new SampleScopeAudienceMapper()),
                        null,
                        clientStore,
                        jwks);
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
        // access token
        var accessToken = response.body.get("access_token");
        var parsedAccessToken = JWSObject.parse((String) accessToken);
        // verify signature
        assertTrue(parsedAccessToken.verify(new ECDSAVerifier(key)));
        assertEquals(parsedAccessToken.getHeader().getAlgorithm(), JWSAlgorithm.ES256);
        assertEquals(parsedAccessToken.getHeader().getType().getType(), "at+JWT");
        // verify claims
        var payload = parsedAccessToken.getPayload().toJSONObject();
        assertEquals(payload.get("sub"), subject);
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
    }

    @Test
    void success_oidc() throws JOSEException, ParseException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                new AuthorizationCode(
                        subject,
                        UUID.randomUUID().toString(),
                        "rs:scope1 openid",
                        "clientId",
                        "xyz",
                        3600,
                        "abc");
        authorizationCodeStore.save(authorizationCode);
        var config =
                new AzIdPConfig(
                        "as.example.com", key.getKeyID(), key.getKeyID(), 3600, 604800, 3600);
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.authorization_code),
                        Set.of(ResponseType.code),
                        "rs:scope1 openid"));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper()),
                        new IDTokenIssuer(config, jwks),
                        new RefreshTokenIssuer(config, jwks, new SampleScopeAudienceMapper()),
                        null,
                        clientStore,
                        jwks);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .code(authorizationCode.code)
                        .grantType("authorization_code")
                        .redirectUri("http://example.com")
                        .clientId("clientId")
                        .authTime(Instant.now().getEpochSecond())
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        {
            var accessToken = response.body.get("access_token");
            var parsedAccessToken = JWSObject.parse((String) accessToken);
            // verify signature
            assertTrue(parsedAccessToken.verify(new ECDSAVerifier(key)));
            assertEquals(parsedAccessToken.getHeader().getAlgorithm(), JWSAlgorithm.ES256);
            assertEquals(parsedAccessToken.getHeader().getType().getType(), "at+JWT");
            // verify claims
            var payload = parsedAccessToken.getPayload().toJSONObject();
            assertEquals(payload.get("sub"), subject);
            assertEquals(payload.get("aud"), List.of("http://rs.example.com"));
            assertEquals(payload.get("client_id"), "clientId");
            assertEquals(payload.get("scope"), "rs:scope1 openid");
            assertNotNull(payload.get("jti"));
            assertEquals(payload.get("iss"), "as.example.com");
            assertTrue((long) payload.get("exp") > Instant.now().getEpochSecond() + 3590);
            assertTrue((long) payload.get("exp") < Instant.now().getEpochSecond() + 3610);
            assertTrue((long) payload.get("iat") > Instant.now().getEpochSecond() - 10);
            assertTrue((long) payload.get("iat") < Instant.now().getEpochSecond() + 10);
            assertEquals(response.body.get("token_type"), "bearer");
            assertEquals(response.body.get("expires_in"), 3600);
        }

        assertTrue(response.body.containsKey("refresh_token"));

        // id token
        {
            var idToken = response.body.get("id_token");
            var parsedIdToken = JWSObject.parse((String) idToken);
            // verify signature
            assertTrue(parsedIdToken.verify(new ECDSAVerifier(key)));
            assertEquals(parsedIdToken.getHeader().getAlgorithm(), JWSAlgorithm.ES256);
            // verify claims
            var payload = parsedIdToken.getPayload().toJSONObject();
            assertEquals(payload.get("sub"), subject);
            assertEquals(payload.get("aud"), "clientId");
            assertNotNull(payload.get("jti"));
            assertEquals(payload.get("iss"), "as.example.com");
            assertTrue((long) payload.get("exp") > Instant.now().getEpochSecond() + 3590);
            assertTrue((long) payload.get("exp") < Instant.now().getEpochSecond() + 3610);
            assertTrue((long) payload.get("iat") > Instant.now().getEpochSecond() - 10);
            assertTrue((long) payload.get("iat") < Instant.now().getEpochSecond() + 10);
            assertEquals(payload.get("nonce"), "abc");
            assertTrue((long) payload.get("auth_time") > Instant.now().getEpochSecond() - 10);
            assertTrue((long) payload.get("auth_time") < Instant.now().getEpochSecond() + 10);
        }
    }

    @Test
    void clientHasNotEnoughScope() throws JOSEException {
        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                new AuthorizationCode(
                        subject, UUID.randomUUID().toString(), "notauthorized", "clientId", "xyz");
        authorizationCodeStore.save(authorizationCode);
        var config =
                new AzIdPConfig(
                        "as.example.com", key.getKeyID(), key.getKeyID(), 3600, 604800, 3600);
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.authorization_code),
                        Set.of(ResponseType.code),
                        "rs:scope1 rs:scope2"));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper()),
                        new IDTokenIssuer(config, jwks),
                        new RefreshTokenIssuer(config, jwks, new SampleScopeAudienceMapper()),
                        null,
                        clientStore,
                        jwks);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .code(authorizationCode.code)
                        .grantType("authorization_code")
                        .redirectUri("http://example.com")
                        .clientId("clientId")
                        .build();

        // exercise
        var tokenResponse = issueToken.issue(tokenRequest);

        // verify
        assertEquals(tokenResponse.status, 400);
        assertEquals("invalid_scope", tokenResponse.body.get("error"));
    }

    @Test
    void usingSameAuthorizationCode() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                new AuthorizationCode(
                        subject, UUID.randomUUID().toString(), "rs:scope1", "clientId", "xyz");
        authorizationCodeStore.save(authorizationCode);
        var config =
                new AzIdPConfig(
                        "as.example.com", key.getKeyID(), key.getKeyID(), 3600, 604800, 3600);
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.authorization_code),
                        Set.of(ResponseType.code),
                        "rs:scope1 rs:scope2"));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper()),
                        new IDTokenIssuer(config, jwks),
                        new RefreshTokenIssuer(config, jwks, new SampleScopeAudienceMapper()),
                        null,
                        clientStore,
                        jwks);
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

        // second time
        var response2 = issueToken.issue(tokenRequest);
        assertEquals(response.status, 200);
        assertEquals(response2.body.get("error"), "invalid_grant");
    }
}
