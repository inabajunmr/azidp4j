package org.azidp4j.revocation;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.Set;
import java.util.stream.Stream;
import org.azidp4j.Fixtures;
import org.azidp4j.client.*;
import org.azidp4j.revocation.request.RevocationRequest;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.refreshtoken.RefreshTokenService;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenService;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenStore;
import org.azidp4j.util.MapUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class RevocationTest {

    private final AccessTokenService accessTokenService =
            new InMemoryAccessTokenService(new InMemoryAccessTokenStore());
    private final RefreshTokenService refreshTokenService =
            new InMemoryRefreshTokenService(new InMemoryRefreshTokenStore());
    private final ClientStore clientStore = new InMemoryClientStore();

    {
        clientStore.save(Fixtures.confidentialClient());
        clientStore.save(Fixtures.publicClient());
    }

    private final Revocation sut =
            new Revocation(accessTokenService, refreshTokenService, clientStore);

    static Stream<Arguments> hints() {
        return Stream.of(
                null, Arguments.arguments("access_token"), Arguments.arguments("refresh_token"));
    }

    @ParameterizedTest
    @MethodSource("hints")
    void accessToken_confidentialClient_success(String tokenTypeHint) {

        // setup
        var at =
                accessTokenService.issue(
                        "sub",
                        "scope1 scope2",
                        "confidential",
                        Instant.now().getEpochSecond(),
                        Instant.now().getEpochSecond(),
                        Set.of("audience"),
                        "code");
        assertTrue(accessTokenService.introspect(at.token).isPresent());

        // exercise
        var response =
                sut.revoke(
                        new RevocationRequest(
                                "confidential",
                                MapUtil.ofNullable(
                                        "token", at.token, "token_type_hint", tokenTypeHint)));

        // verify
        assertEquals(200, response.status);
        assertFalse(accessTokenService.introspect(at.token).isPresent());
    }

    @ParameterizedTest
    @MethodSource("hints")
    void accessToken_publicClient_success(String tokenTypeHint) {

        // setup
        var at =
                accessTokenService.issue(
                        "sub",
                        "scope1 scope2",
                        "public",
                        Instant.now().getEpochSecond(),
                        Instant.now().getEpochSecond(),
                        Set.of("audience"),
                        "code");
        assertTrue(accessTokenService.introspect(at.token).isPresent());

        // exercise
        var response =
                sut.revoke(
                        new RevocationRequest(
                                "public",
                                MapUtil.ofNullable(
                                        "token", at.token, "token_type_hint", tokenTypeHint)));

        // verify
        assertEquals(200, response.status);
        assertFalse(accessTokenService.introspect(at.token).isPresent());
    }

    @ParameterizedTest
    @MethodSource("hints")
    void notFound(String tokenTypeHint) {

        // exercise
        var response =
                sut.revoke(
                        new RevocationRequest(
                                "confidential",
                                MapUtil.ofNullable(
                                        "token", "not found", "token_type_hint", tokenTypeHint)));

        // verify
        assertEquals(200, response.status);
    }

    @ParameterizedTest
    @MethodSource("hints")
    void tokenIsNull(String tokenTypeHint) {

        // exercise
        var response =
                sut.revoke(
                        new RevocationRequest(
                                "confidential",
                                MapUtil.ofNullable(
                                        "token", null, "token_type_hint", tokenTypeHint)));

        // verify
        assertEquals(200, response.status);
    }

    @ParameterizedTest
    @MethodSource("hints")
    void refreshToken_confidentialClient_success(String tokenTypeHint) {

        // setup
        var rt =
                refreshTokenService.issue(
                        "sub",
                        "scope1 scope2",
                        "confidential",
                        Instant.now().getEpochSecond(),
                        Instant.now().getEpochSecond(),
                        Set.of("audience"),
                        "code");
        assertTrue(refreshTokenService.introspect(rt.token).isPresent());

        // exercise
        var response =
                sut.revoke(
                        new RevocationRequest(
                                "confidential",
                                MapUtil.ofNullable(
                                        "token", rt.token, "token_type_hint", tokenTypeHint)));

        // verify
        assertEquals(200, response.status);
        assertFalse(refreshTokenService.introspect(rt.token).isPresent());
    }

    @ParameterizedTest
    @MethodSource("hints")
    void refreshToken_publicClient_success(String tokenTypeHint) {

        // setup
        var rt =
                refreshTokenService.issue(
                        "sub",
                        "scope1 scope2",
                        "public",
                        Instant.now().getEpochSecond(),
                        Instant.now().getEpochSecond(),
                        Set.of("audience"),
                        "code");
        assertTrue(refreshTokenService.introspect(rt.token).isPresent());

        // exercise
        var response =
                sut.revoke(
                        new RevocationRequest(
                                "confidential",
                                MapUtil.ofNullable(
                                        "token", rt.token, "token_type_hint", tokenTypeHint)));

        // verify
        assertEquals(200, response.status);
        assertFalse(refreshTokenService.introspect(rt.token).isPresent());
    }

    @Test
    void accessToken_clientNotFound() {

        // setup
        var rt =
                accessTokenService.issue(
                        "sub",
                        "scope1 scope2",
                        "confidential",
                        Instant.now().getEpochSecond(),
                        Instant.now().getEpochSecond(),
                        Set.of("audience"),
                        "code");
        assertTrue(accessTokenService.introspect(rt.token).isPresent());
        clientStore.remove("confidential");

        // exercise
        var response =
                sut.revoke(
                        new RevocationRequest(
                                "confidential",
                                MapUtil.ofNullable("token", rt.token, "token_type_hint", null)));

        // verify
        assertEquals(200, response.status);
        assertFalse(refreshTokenService.introspect(rt.token).isPresent());
        clientStore.save(Fixtures.confidentialClient());
    }

    @Test
    void refreshToken_clientNotFound() {

        // setup
        var rt =
                refreshTokenService.issue(
                        "sub",
                        "scope1 scope2",
                        "confidential",
                        Instant.now().getEpochSecond(),
                        Instant.now().getEpochSecond(),
                        Set.of("audience"),
                        "code");
        assertTrue(refreshTokenService.introspect(rt.token).isPresent());
        clientStore.remove("confidential");

        // exercise
        var response =
                sut.revoke(
                        new RevocationRequest(
                                "confidential",
                                MapUtil.ofNullable("token", rt.token, "token_type_hint", null)));

        // verify
        assertEquals(200, response.status);
        assertFalse(refreshTokenService.introspect(rt.token).isPresent());
        clientStore.save(Fixtures.confidentialClient());
    }

    @Test
    void illegalTokenTypeHint() {
        // exercise
        var response =
                sut.revoke(
                        new RevocationRequest(
                                "confidential",
                                MapUtil.ofNullable(
                                        "token", "token", "token_type_hint", "illegal")));

        // verify
        assertEquals(400, response.status);
    }

    @Test
    void illegalType() {

        // exercise
        var response =
                sut.revoke(
                        new RevocationRequest(
                                "confidential",
                                MapUtil.ofNullable("token", 100, "token_type_hint", null)));

        // verify
        assertEquals(400, response.status);
    }
}
