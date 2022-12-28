package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.jwk.JWKSet;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeStore;
import org.azidp4j.authorize.request.InternalAuthorizationRequest;
import org.azidp4j.authorize.request.ResponseMode;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.authorize.response.NextAction;
import org.azidp4j.client.*;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.SampleIdTokenKidSupplier;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenValidator;
import org.junit.jupiter.api.Test;

class AuthorizeTest_None {

    @Test
    void none() {
        // setup
        var clientStore = new InMemoryClientStore();
        var client =
                new Client(
                        "client1",
                        "clientSecret",
                        Set.of("http://rp1.example.com", "http://rp2.example.com"),
                        Set.of(Set.of(ResponseType.none)),
                        ApplicationType.WEB,
                        Set.of(),
                        null,
                        null,
                        null,
                        "rs:scope1 rs:scope2",
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        TokenEndpointAuthMethod.client_secret_basic,
                        null,
                        SigningAlgorithm.ES256,
                        null,
                        null,
                        List.of("acr1"),
                        null);
        clientStore.save(client);
        var config =
                new AzIdPConfig(
                        "http://localhost:8080",
                        Set.of("openid", "scope1", "scope2", "default"),
                        Set.of("openid", "scope1"),
                        Set.of(TokenEndpointAuthMethod.client_secret_basic),
                        null,
                        Set.of(TokenEndpointAuthMethod.client_secret_basic),
                        null,
                        Set.of(TokenEndpointAuthMethod.client_secret_basic),
                        null,
                        Set.of(GrantType.authorization_code),
                        Set.of(Set.of(ResponseType.none)),
                        Set.of(ResponseMode.query, ResponseMode.fragment),
                        Set.of(SigningAlgorithm.none),
                        Duration.ofSeconds(3600),
                        Duration.ofSeconds(600),
                        Duration.ofSeconds(604800),
                        Duration.ofSeconds(3600));
        var scopeAudienceMapper = new SampleScopeAudienceMapper();
        var jwks = new JWKSet();
        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                        scopeAudienceMapper,
                        new InMemoryAccessTokenService(new InMemoryAccessTokenStore()),
                        new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks), null),
                        new IDTokenValidator(config, jwks),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("none")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserSubject("username")
                        .state("xyz")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertNotNull(queryMap.get("state"));
        assertNull(queryMap.get("access_token"));
        assertNull(queryMap.get("code"));
        assertNull(queryMap.get("id_token"));
    }
}
