package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AccessTokenAssert;
import org.azidp4j.Fixtures;
import org.azidp4j.IdTokenAssert;
import org.azidp4j.client.Client;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.TokenEndpointAuthMethod;
import org.azidp4j.token.accesstoken.AccessTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.junit.jupiter.api.Test;

class AuthorizeTest_Implicit {

    ClientStore clientStore = new InMemoryClientStore();
    Client client =
            new Client(
                    "client1",
                    "clientSecret",
                    Set.of("http://rp1.example.com", "http://rp2.example.com"),
                    Set.of(GrantType.authorization_code),
                    Set.of(ResponseType.code),
                    "scope1 scope2 openid",
                    TokenEndpointAuthMethod.client_secret_basic);
    Client noGrantTypesClient =
            new Client(
                    "noGrantTypesClient",
                    "clientSecret",
                    Set.of("http://rp1.example.com"),
                    Set.of(),
                    Set.of(ResponseType.code),
                    "scope1 scope2",
                    TokenEndpointAuthMethod.client_secret_basic);

    Client noResponseTypesClient =
            new Client(
                    "noResponseTypesClient",
                    "clientSecret",
                    Set.of("http://rp1.example.com"),
                    Set.of(GrantType.authorization_code, GrantType.implicit),
                    Set.of(),
                    "scope1 scope2",
                    TokenEndpointAuthMethod.client_secret_basic);

    public AuthorizeTest_Implicit() {
        clientStore.save(client);
        clientStore.save(noGrantTypesClient);
        clientStore.save(noResponseTypesClient);
    }

    @Test
    void implicitGrant_withoutState() throws JOSEException, ParseException {
        // setup
        var clientStore = new InMemoryClientStore();
        var client =
                new Client(
                        "client1",
                        "clientSecret",
                        Set.of("http://rp1.example.com", "http://rp2.example.com"),
                        Set.of(GrantType.implicit),
                        Set.of(ResponseType.token),
                        "rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic);
        clientStore.save(client);
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var config = Fixtures.azIdPConfig(key.getKeyID());

        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeStore(),
                        new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper()),
                        new IDTokenIssuer(config, new JWKSet()),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.status, 302);
        var location = response.headers().get("Location");
        var fragmentMap =
                Arrays.stream(URI.create(location).getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertNull(fragmentMap.get("state"));
        AccessTokenAssert.assertAccessToken(
                fragmentMap.get("access_token"),
                key,
                "username",
                "http://rs.example.com",
                "client1",
                "rs:scope1",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond());
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
    }

    @Test
    void implicitGrant_withState() throws JOSEException, ParseException {
        // setup
        var clientStore = new InMemoryClientStore();
        var client =
                new Client(
                        "client1",
                        "clientSecret",
                        Set.of("http://rp1.example.com", "http://rp2.example.com"),
                        Set.of(GrantType.implicit),
                        Set.of(ResponseType.token),
                        "rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic);
        clientStore.save(client);
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeStore(),
                        new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper()),
                        new IDTokenIssuer(config, new JWKSet()),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .state("xyz")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.status, 302);
        var location = response.headers().get("Location");
        var fragmentMap =
                Arrays.stream(URI.create(location).getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(fragmentMap.get("state"), "xyz");
        AccessTokenAssert.assertAccessToken(
                fragmentMap.get("access_token"),
                key,
                "username",
                "http://rs.example.com",
                "client1",
                "rs:scope1",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond());
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
    }

    @Test
    void implicitGrant_oidc_withState() throws JOSEException, ParseException {
        // setup
        var clientStore = new InMemoryClientStore();
        var client =
                new Client(
                        "client1",
                        "clientSecret",
                        Set.of("http://rp1.example.com", "http://rp2.example.com"),
                        Set.of(GrantType.implicit),
                        Set.of(ResponseType.token, ResponseType.id_token),
                        "openid rs:scope1 rs:scope2",
                        TokenEndpointAuthMethod.client_secret_basic);
        clientStore.save(client);
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var config = Fixtures.azIdPConfig(key.getKeyID());
        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeStore(),
                        new AccessTokenIssuer(config, jwks, new SampleScopeAudienceMapper()),
                        new IDTokenIssuer(config, jwks),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token id_token")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("openid rs:scope1")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("openid", "rs:scope1", "rs:scope2"))
                        .state("xyz")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.status, 302);
        var location = response.headers().get("Location");
        var fragmentMap =
                Arrays.stream(URI.create(location).getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(fragmentMap.get("state"), "xyz");
        AccessTokenAssert.assertAccessToken(
                fragmentMap.get("access_token"),
                key,
                "username",
                "http://rs.example.com",
                "client1",
                "openid rs:scope1",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond());
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
        IdTokenAssert.assertIdToken(
                fragmentMap.get("id_token"),
                key,
                "username",
                "client1",
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                null,
                fragmentMap.get("access_token"),
                null);
    }
}
