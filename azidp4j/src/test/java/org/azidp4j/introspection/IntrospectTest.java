package org.azidp4j.introspection;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.accesstoken.*;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessToken;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.refreshtoken.InMemoryRefreshTokenStore;
import org.azidp4j.token.refreshtoken.RefreshToken;
import org.azidp4j.token.refreshtoken.RefreshTokenStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class IntrospectTest {

    RefreshTokenStore refreshTokenStore = new InMemoryRefreshTokenStore();
    AzIdPConfig config = Fixtures.azIdPConfig("test");
    InMemoryAccessTokenStore accessTokenStore = new InMemoryAccessTokenStore();
    AccessTokenService accessTokenService =
            new InMemoryAccessTokenService(
                    config, new SampleScopeAudienceMapper(), accessTokenStore);
    Introspect introspect = new Introspect(accessTokenService, refreshTokenStore, config);

    static Stream<Arguments> hints() {
        return Stream.of(
                null, Arguments.arguments("access_token"), Arguments.arguments("refresh_token"));
    }

    @ParameterizedTest
    @MethodSource("hints")
    void accessToken_success(String tokenTypeHint) {

        // setup
        var at = saveTestAccessToken(Instant.now().getEpochSecond() + 100);

        // exercise
        var actual =
                introspect.introspect(
                        InternalIntrospectionRequest.builder()
                                .token(at.getToken())
                                .tokenTypeHint(tokenTypeHint)
                                .build());

        // verify
        assertEquals(actual.status, 200);
        assertAccessTokenIntrospectionResult(at, actual.body);
    }

    @ParameterizedTest
    @MethodSource("hints")
    void accessToken_notFound() {
        // exercise
        var actual =
                introspect.introspect(
                        InternalIntrospectionRequest.builder()
                                .token("not found")
                                .tokenTypeHint(null)
                                .build());

        // verify
        assertEquals(actual.status, 200);
        assertEquals(false, actual.body.get("active"));
    }

    @ParameterizedTest
    @MethodSource("hints")
    void accessToken_expired() {
        // setup
        Introspect sut = new Introspect(accessTokenService, refreshTokenStore, config);
        var at = saveTestAccessToken(Instant.now().getEpochSecond() + -1);

        // exercise
        var actual =
                sut.introspect(
                        InternalIntrospectionRequest.builder()
                                .token(at.getToken())
                                .tokenTypeHint(null)
                                .build());

        // verify
        assertEquals(actual.status, 200);
        assertEquals(false, actual.body.get("active"));
    }

    @ParameterizedTest
    @MethodSource("hints")
    void refreshToken_success(String tokenTypeHint) {

        // setup
        var rt = saveTestRefreshToken(Instant.now().getEpochSecond() + 100);

        // exercise
        var actual =
                introspect.introspect(
                        InternalIntrospectionRequest.builder()
                                .token(rt.token)
                                .tokenTypeHint(tokenTypeHint)
                                .build());

        // verify
        assertEquals(actual.status, 200);
        assertRefreshTokenIntrospectionResult(rt, actual.body);
    }

    @ParameterizedTest
    @MethodSource("hints")
    void refreshToken_expired() {
        // setup
        var rt = saveTestRefreshToken(Instant.now().getEpochSecond() + -1);

        // exercise
        var actual =
                introspect.introspect(
                        InternalIntrospectionRequest.builder()
                                .token(rt.token)
                                .tokenTypeHint(null)
                                .build());

        // verify
        assertEquals(actual.status, 200);
        assertEquals(false, actual.body.get("active"));
    }

    @Test
    void tokenIsNull() {
        // exercise
        var actual =
                introspect.introspect(InternalIntrospectionRequest.builder().token(null).build());

        // verify
        assertEquals(actual.status, 400);
    }

    private AccessToken saveTestAccessToken(long exp) {
        var at =
                new InMemoryAccessToken(
                        UUID.randomUUID().toString(),
                        "sub",
                        "scope1 scope2",
                        "clientId",
                        Set.of("aud"),
                        exp,
                        Instant.now().getEpochSecond());
        accessTokenStore.save(at);
        return at;
    }

    private RefreshToken saveTestRefreshToken(long exp) {
        var rt =
                new RefreshToken(
                        UUID.randomUUID().toString(),
                        "sub",
                        "scope1 scope2",
                        "clientId",
                        Set.of("aud"),
                        exp,
                        Instant.now().getEpochSecond());
        refreshTokenStore.save(rt);
        return rt;
    }

    private void assertAccessTokenIntrospectionResult(
            AccessToken expected, Map<String, Object> actualResponse) {
        assertEquals(true, actualResponse.get("active"));
        assertEquals(expected.getScope(), actualResponse.get("scope"));
        assertEquals(expected.getClientId(), actualResponse.get("client_id"));
        assertEquals("bearer", actualResponse.get("token_type"));
        assertEquals(expected.getExpiresAtEpochSec(), actualResponse.get("exp"));
        assertEquals(expected.getIssuedAtEpochSec(), actualResponse.get("iat"));
        assertEquals(expected.getSub(), actualResponse.get("sub"));
        assertEquals(expected.getAudience(), actualResponse.get("aud"));
        assertEquals(config.issuer, actualResponse.get("iss"));
    }

    private void assertRefreshTokenIntrospectionResult(
            RefreshToken expected, Map<String, Object> actualResponse) {
        assertEquals(true, actualResponse.get("active"));
        assertEquals(expected.scope, actualResponse.get("scope"));
        assertEquals(expected.clientId, actualResponse.get("client_id"));
        assertEquals("bearer", actualResponse.get("token_type"));
        assertEquals(expected.expiresAtEpochSec, actualResponse.get("exp"));
        assertEquals(expected.issuedAtEpochSec, actualResponse.get("iat"));
        assertEquals(expected.sub, actualResponse.get("sub"));
        assertEquals(expected.audience, actualResponse.get("aud"));
        assertEquals(config.issuer, actualResponse.get("iss"));
    }
}
