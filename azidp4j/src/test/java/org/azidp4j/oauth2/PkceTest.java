package org.azidp4j.oauth2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.nimbusds.jose.jwk.JWKSet;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.request.AuthorizationRequest;
import org.azidp4j.authorize.response.NextAction;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.token.request.TokenRequest;
import org.junit.jupiter.api.Test;

public class PkceTest {

    @Test
    void defaultCodeChallengeMethod() {
        // setup
        var clientStore = new InMemoryClientStore();
        var client = Fixtures.publicClient();
        clientStore.save(client);
        var sut = Fixtures.azIdPBuilder(new JWKSet()).customClientStore(clientStore).build();

        // authorization request
        var redirectUri = "http://rp1.example.com";
        var queryParameters =
                Map.of(
                        "client_id",
                        client.clientId,
                        "redirect_uri",
                        redirectUri,
                        "response_type",
                        "code",
                        "scope",
                        "rs:scope1 rs:scope2",
                        "code_challenge",
                        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        "state",
                        "xyz");
        var authorizationRequest =
                new AuthorizationRequest(
                        "username",
                        Instant.now().getEpochSecond(),
                        Set.of("rs:scope1", "rs:scope2"),
                        queryParameters);

        // exercise
        var authorizationResponse = sut.authorize(authorizationRequest);

        // verify
        assertEquals(authorizationResponse.next, NextAction.redirect);
        var queryMap =
                Arrays.stream(
                                URI.create(authorizationResponse.redirect.redirectTo)
                                        .getQuery()
                                        .split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(queryMap.get("state"), "xyz");

        // token request
        var tokenRequestBody1 =
                Map.of(
                        "code",
                        (Object) queryMap.get("code"),
                        "redirect_uri",
                        redirectUri,
                        "grant_type",
                        "authorization_code",
                        "code_verifier",
                        // default code_challenge_method is S256
                        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        var tokenRequest1 = new TokenRequest(client.clientId, tokenRequestBody1);

        // exercise
        var tokenResponse1 = sut.issueToken(tokenRequest1);

        // verify
        assertNotNull(tokenResponse1.body.get("access_token"));
    }

    @Test
    void s256CodeChallengeMethod() {
        // setup
        var clientStore = new InMemoryClientStore();
        var client = Fixtures.publicClient();
        clientStore.save(client);
        var sut = Fixtures.azIdPBuilder(new JWKSet()).customClientStore(clientStore).build();

        // authorization request
        var redirectUri = "http://rp1.example.com";
        var queryParameters =
                Map.of(
                        "client_id",
                        client.clientId,
                        "redirect_uri",
                        redirectUri,
                        "response_type",
                        "code",
                        "scope",
                        "rs:scope1 rs:scope2",
                        "code_challenge",
                        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        "code_challenge_method",
                        "S256",
                        "state",
                        "xyz");
        var authorizationRequest =
                new AuthorizationRequest(
                        "username",
                        Instant.now().getEpochSecond(),
                        Set.of("rs:scope1", "rs:scope2"),
                        queryParameters);

        // exercise
        var authorizationResponse = sut.authorize(authorizationRequest);

        // verify
        assertEquals(authorizationResponse.next, NextAction.redirect);
        var queryMap =
                Arrays.stream(
                                URI.create(authorizationResponse.redirect.redirectTo)
                                        .getQuery()
                                        .split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(queryMap.get("state"), "xyz");

        // token request
        var tokenRequestBody1 =
                Map.of(
                        "code",
                        (Object) queryMap.get("code"),
                        "redirect_uri",
                        redirectUri,
                        "grant_type",
                        "authorization_code",
                        "code_verifier",
                        // default code_challenge_method is S256
                        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        var tokenRequest1 = new TokenRequest(client.clientId, tokenRequestBody1);

        // exercise
        var tokenResponse1 = sut.issueToken(tokenRequest1);

        // verify
        assertNotNull(tokenResponse1.body.get("access_token"));
    }

    @Test
    void plainCodeChallengeMethod() {
        // setup
        var clientStore = new InMemoryClientStore();
        var client = Fixtures.publicClient();
        clientStore.save(client);
        var sut = Fixtures.azIdPBuilder(new JWKSet()).customClientStore(clientStore).build();

        // authorization request
        var redirectUri = "http://rp1.example.com";
        var queryParameters =
                Map.of(
                        "client_id",
                        client.clientId,
                        "redirect_uri",
                        redirectUri,
                        "response_type",
                        "code",
                        "scope",
                        "rs:scope1 rs:scope2",
                        "code_challenge",
                        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        "code_challenge_method",
                        "PLAIN",
                        "state",
                        "xyz");
        var authorizationRequest =
                new AuthorizationRequest(
                        "username",
                        Instant.now().getEpochSecond(),
                        Set.of("rs:scope1", "rs:scope2"),
                        queryParameters);

        // exercise
        var authorizationResponse = sut.authorize(authorizationRequest);

        // verify
        assertEquals(authorizationResponse.next, NextAction.redirect);
        var queryMap =
                Arrays.stream(
                                URI.create(authorizationResponse.redirect.redirectTo)
                                        .getQuery()
                                        .split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(queryMap.get("state"), "xyz");

        // token request
        var tokenRequestBody1 =
                Map.of(
                        "code",
                        (Object) queryMap.get("code"),
                        "redirect_uri",
                        redirectUri,
                        "grant_type",
                        "authorization_code",
                        "code_verifier",
                        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        var tokenRequest1 = new TokenRequest(client.clientId, tokenRequestBody1);

        // exercise
        var tokenResponse1 = sut.issueToken(tokenRequest1);

        // verify
        assertNotNull(tokenResponse1.body.get("access_token"));
    }
}
