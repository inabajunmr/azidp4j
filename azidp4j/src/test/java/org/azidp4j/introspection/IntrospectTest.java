package org.azidp4j.introspection;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.introspection.request.IntrospectionRequest;
import org.azidp4j.token.accesstoken.*;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.refreshtoken.RefreshToken;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenService;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenStore;
import org.azidp4j.util.MapUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class IntrospectTest {

    final InMemoryRefreshTokenStore inMemoryRefreshTokenStore = new InMemoryRefreshTokenStore();
    final AzIdPConfig config = Fixtures.azIdPConfig();
    final InMemoryAccessTokenStore accessTokenStore = new InMemoryAccessTokenStore();
    final AccessTokenService accessTokenService = new InMemoryAccessTokenService(accessTokenStore);
    final Introspect introspect =
            new Introspect(
                    accessTokenService,
                    new InMemoryRefreshTokenService(inMemoryRefreshTokenStore),
                    config);

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
                        new IntrospectionRequest(
                                MapUtil.ofNullable(
                                        "token", at.token, "token_type_hint", tokenTypeHint)));

        // verify
        assertEquals(actual.status, 200);
        assertAccessTokenIntrospectionResult(at, actual.body);
    }

    @ParameterizedTest
    @MethodSource("hints")
    void accessToken_notFound(String tokenTypeHint) {
        // exercise
        var actual =
                introspect.introspect(
                        new IntrospectionRequest(
                                MapUtil.ofNullable(
                                        "token", "not found", "token_type_hint", tokenTypeHint)));

        // verify
        assertEquals(actual.status, 200);
        assertEquals(false, actual.body.get("active"));
    }

    @ParameterizedTest
    @MethodSource("hints")
    void accessToken_expired(String tokenTypeHint) {
        // setup
        Introspect sut =
                new Introspect(
                        accessTokenService,
                        new InMemoryRefreshTokenService(inMemoryRefreshTokenStore),
                        config);
        var at = saveTestAccessToken(Instant.now().getEpochSecond() - 1);

        // exercise

        var actual =
                sut.introspect(
                        new IntrospectionRequest(
                                MapUtil.ofNullable(
                                        "token", at.token, "token_type_hint", tokenTypeHint)));

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
                        new IntrospectionRequest(
                                MapUtil.ofNullable(
                                        "token", rt.token, "token_type_hint", tokenTypeHint)));

        // verify
        assertEquals(actual.status, 200);
        assertRefreshTokenIntrospectionResult(rt, actual.body);
    }

    @ParameterizedTest
    @MethodSource("hints")
    void refreshToken_expired(String tokenTypeHint) {
        // setup
        var rt = saveTestRefreshToken(Instant.now().getEpochSecond() - 1);

        // exercise
        var actual =
                introspect.introspect(
                        new IntrospectionRequest(
                                MapUtil.ofNullable(
                                        "token", rt.token, "token_type_hint", tokenTypeHint)));

        // verify
        assertEquals(actual.status, 200);
        assertEquals(false, actual.body.get("active"));
    }

    @Test
    void tokenIsNull() {
        // exercise
        var actual =
                introspect.introspect(
                        new IntrospectionRequest(
                                MapUtil.ofNullable("token", null, "token_type_hint", null)));

        // verify
        assertEquals(actual.status, 400);
    }

    @Test
    void illegalType() {
        // exercise
        var actual =
                introspect.introspect(
                        new IntrospectionRequest(
                                MapUtil.ofNullable("token", 100, "token_type_hint", null)));

        // verify
        assertEquals(actual.status, 400);
    }

    @Test
    void illegalTokenTypeHint() {
        var at = saveTestAccessToken(Instant.now().getEpochSecond() + 100);

        // exercise
        var actual =
                introspect.introspect(
                        new IntrospectionRequest(
                                MapUtil.ofNullable(
                                        "token", at.token, "token_type_hint", "illegal")));

        // verify
        assertEquals(actual.status, 400);
    }

    private AccessToken saveTestAccessToken(long exp) {
        var at =
                new AccessToken(
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
        inMemoryRefreshTokenStore.save(rt);
        return rt;
    }

    private void assertAccessTokenIntrospectionResult(
            AccessToken expected, Map<String, Object> actualResponse) {
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
