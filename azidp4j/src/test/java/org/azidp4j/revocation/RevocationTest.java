package org.azidp4j.revocation;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.Set;
import java.util.stream.Stream;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.*;
import org.azidp4j.revocation.request.InternalRevocationRequest;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.refreshtoken.RefreshTokenService;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenService;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenStore;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class RevocationTest {

    AccessTokenService accessTokenService =
            new InMemoryAccessTokenService(new InMemoryAccessTokenStore());
    RefreshTokenService refreshTokenService =
            new InMemoryRefreshTokenService(new InMemoryRefreshTokenStore());
    ClientStore clientStore = new InMemoryClientStore();

    {
        clientStore.save(
                new Client(
                        "confidential",
                        "secret",
                        null,
                        Set.of(GrantType.authorization_code),
                        Set.of(ResponseType.code),
                        "scope1 scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        SigningAlgorithm.ES256));
        clientStore.save(
                new Client(
                        "public",
                        "secret",
                        null,
                        Set.of(GrantType.authorization_code),
                        Set.of(ResponseType.code),
                        "scope1 scope2",
                        TokenEndpointAuthMethod.none,
                        SigningAlgorithm.ES256));
    }

    Revocation sut = new Revocation(accessTokenService, refreshTokenService, clientStore);

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
        assertTrue(accessTokenService.introspect(at.getToken()).isPresent());

        // exercise
        sut.revoke(
                InternalRevocationRequest.builder()
                        .authenticatedClientId("confidential")
                        .token(at.getToken())
                        .tokenTypeHint(tokenTypeHint)
                        .build());

        // verify
        assertFalse(accessTokenService.introspect(at.getToken()).isPresent());
    }

    @ParameterizedTest
    @MethodSource("hints")
    void notFound(String tokenTypeHint) {

        // exercise
        sut.revoke(
                InternalRevocationRequest.builder()
                        .authenticatedClientId("confidential")
                        .token("not found")
                        .tokenTypeHint(tokenTypeHint)
                        .build());
    }

    @ParameterizedTest
    @MethodSource("hints")
    void tokenIsNull(String tokenTypeHint) {

        // exercise
        sut.revoke(
                InternalRevocationRequest.builder()
                        .authenticatedClientId("confidential")
                        .token(null)
                        .tokenTypeHint(tokenTypeHint)
                        .build());
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
        sut.revoke(
                InternalRevocationRequest.builder()
                        .authenticatedClientId("confidential")
                        .token(rt.token)
                        .tokenTypeHint(tokenTypeHint)
                        .build());

        // verify
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
        sut.revoke(
                InternalRevocationRequest.builder()
                        .authenticatedClientId(null)
                        .token(rt.token)
                        .tokenTypeHint(tokenTypeHint)
                        .build());

        // verify
        assertFalse(refreshTokenService.introspect(rt.token).isPresent());
    }
}
