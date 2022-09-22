package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.jwk.JWKSet;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.client.Client;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.accesstoken.AccessTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.junit.jupiter.api.Test;

class AuthorizeTest_AuthorizationCode {

    ClientStore clientStore = new InMemoryClientStore();
    Client client =
            new Client(
                    "client1",
                    "clientSecret",
                    Set.of("http://rp1.example.com", "http://rp2.example.com"),
                    Set.of(GrantType.authorization_code),
                    Set.of(ResponseType.code),
                    "scope1 scope2 openid");
    Client noGrantTypesClient =
            new Client(
                    "noGrantTypesClient",
                    "clientSecret",
                    Set.of("http://rp1.example.com"),
                    Set.of(),
                    Set.of(ResponseType.code),
                    "scope1 scope2");

    Client noResponseTypesClient =
            new Client(
                    "noResponseTypesClient",
                    "clientSecret",
                    Set.of("http://rp1.example.com"),
                    Set.of(GrantType.authorization_code, GrantType.implicit),
                    Set.of(),
                    "scope1 scope2");
    AzIdPConfig config = new AzIdPConfig("issuer", "kid", "kid", 3600, 604800, 3600);
    Authorize sut =
            new Authorize(
                    clientStore,
                    new InMemoryAuthorizationCodeStore(),
                    new AccessTokenIssuer(config, new JWKSet(), new SampleScopeAudienceMapper()),
                    new IDTokenIssuer(config, new JWKSet()),
                    config);

    public AuthorizeTest_AuthorizationCode() {
        clientStore.save(client);
        clientStore.save(noGrantTypesClient);
        clientStore.save(noResponseTypesClient);
    }

    @Test
    void authorizationCodeGrant_withoutState() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("scope1")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("scope1", "scope2"))
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.status, 302);
        var location = response.headers("http://rp1.example.com").get("Location");
        var queryMap =
                Arrays.stream(URI.create(location).getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertNull(queryMap.get("state"));
        assertNotNull(queryMap.get("code"));
    }

    @Test
    void authorizationCodeGrant_withState() {
        // setup
        var clientStore = new InMemoryClientStore();
        var client =
                new Client(
                        "client1",
                        "clientSecret",
                        Set.of("http://rp1.example.com", "http://rp2.example.com"),
                        Set.of(GrantType.authorization_code),
                        Set.of(ResponseType.code),
                        "scope1 scope2");
        clientStore.save(client);
        var config = new AzIdPConfig("issuer", "kid", "kid", 3600, 604800, 3600);
        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeStore(),
                        new AccessTokenIssuer(
                                config, new JWKSet(), new SampleScopeAudienceMapper()),
                        new IDTokenIssuer(config, new JWKSet()),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("scope1")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("scope1", "scope2"))
                        .state("xyz")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.status, 302);
        var location = response.headers("http://rp1.example.com").get("Location");
        var queryMap =
                Arrays.stream(URI.create(location).getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(queryMap.get("state"), "xyz");
        assertNotNull(queryMap.get("code"));
    }

    @Test
    void authorizationCodeGrant_withMaxAge() {
        // setup
        var clientStore = new InMemoryClientStore();
        var client =
                new Client(
                        "client1",
                        "clientSecret",
                        Set.of("http://rp1.example.com"),
                        Set.of(GrantType.authorization_code),
                        Set.of(ResponseType.code),
                        "scope1 scope2");
        clientStore.save(client);
        var config = new AzIdPConfig("issuer", "kid", "kid", 3600, 604800, 3600);
        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeStore(),
                        new AccessTokenIssuer(
                                config, new JWKSet(), new SampleScopeAudienceMapper()),
                        new IDTokenIssuer(config, new JWKSet()),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .maxAge("10")
                        .redirectUri("http://rp1.example.com")
                        .scope("scope1")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("scope1", "scope2"))
                        .state("xyz")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.status, 302);
        var location = response.headers("http://rp1.example.com").get("Location");
        var queryMap =
                Arrays.stream(URI.create(location).getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(queryMap.get("state"), "xyz");
        assertNotNull(queryMap.get("code"));
    }
}
