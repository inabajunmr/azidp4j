package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.client.Client;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.token.AccessTokenIssuer;
import org.junit.jupiter.api.Test;

class AuthorizeTest {

    @Test
    void validationError() {
        var clientStore = new InMemoryClientStore();
        var client =
                new Client(
                        "client1",
                        "clientSecret",
                        Set.of("http://example.com"),
                        Set.of(GrantType.authorization_code),
                        Set.of(ResponseType.code),
                        "scope1 scope2");
        clientStore.save(client);
        var config = new AzIdPConfig("issuer", "kid", 3600);
        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeStore(),
                        new AccessTokenIssuer(config, new JWKSet()),
                        config);
        // response type is null
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .clientId(client.clientId)
                            .redirectUri("http://example.com")
                            .scope("scope1")
                            .sub("username")
                            .state("xyz")
                            .build();
            var response = sut.authorize(authorizationRequest);
            assertEquals(response.status, 400);
        }
        // illegal response type
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .clientId(client.clientId)
                            .redirectUri("http://example.com")
                            .scope("scope1")
                            .sub("username")
                            .state("xyz")
                            .build();
            var response = sut.authorize(authorizationRequest);
            assertEquals(response.status, 400);
        }
        // client id is null
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .redirectUri("http://example.com")
                            .scope("scope1")
                            .sub("username")
                            .state("xyz")
                            .build();
            var response = sut.authorize(authorizationRequest);
            assertEquals(response.status, 400);
        }
        // client not exist
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId("unknown")
                            .redirectUri("http://example.com")
                            .scope("scope1")
                            .sub("username")
                            .state("xyz")
                            .build();
            var response = sut.authorize(authorizationRequest);
            assertEquals(response.status, 400);
        }
        // unauthorized redirect uri
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://not.authorized.example.com")
                            .scope("scope1")
                            .sub("username")
                            .state("xyz")
                            .build();
            var response = sut.authorize(authorizationRequest);
            assertEquals(response.status, 400);
        }
        // unauthorized scope
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://example.com")
                            .scope("invalid")
                            .sub("username")
                            .state("xyz")
                            .build();
            var response = sut.authorize(authorizationRequest);
            assertEquals(response.status, 302);
            var location = URI.create(response.headers("http://example.com").get("Location"));
            assertEquals("example.com", location.getHost());
            var queryMap =
                    Arrays.stream(location.getQuery().split("&"))
                            .collect(
                                    Collectors.toMap(
                                            kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
            assertEquals("xyz", queryMap.get("state"));
            assertEquals("invalid_scope", queryMap.get("error"));
        }
        // client doesn't support grant type
        var noGrantTypesClient =
                new Client(
                        "clientId",
                        "clientSecret",
                        Set.of("http://example.com"),
                        Set.of(),
                        Set.of(ResponseType.code),
                        "scope1 scope2");
        clientStore.save(noGrantTypesClient);
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(noGrantTypesClient.clientId)
                            .redirectUri("http://example.com")
                            .scope("scope1")
                            .sub("username")
                            .state("xyz")
                            .build();
            var response = sut.authorize(authorizationRequest);
            assertEquals(response.status, 302);
            var location = URI.create(response.headers("http://example.com").get("Location"));
            assertEquals("example.com", location.getHost());
            var queryMap =
                    Arrays.stream(location.getQuery().split("&"))
                            .collect(
                                    Collectors.toMap(
                                            kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
            assertEquals("xyz", queryMap.get("state"));
            assertEquals("unauthorized_client", queryMap.get("error"));
        }
        // client doesn't support response type
        var noResponseTypesClient =
                new Client(
                        "clientId",
                        "clientSecret",
                        Set.of("http://example.com"),
                        Set.of(GrantType.authorization_code),
                        Set.of(),
                        "scope1 scope2");
        clientStore.save(noResponseTypesClient);
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(noResponseTypesClient.clientId)
                            .redirectUri("http://example.com")
                            .scope("scope1")
                            .sub("username")
                            .state("xyz")
                            .build();
            var response = sut.authorize(authorizationRequest);
            assertEquals(response.status, 302);
            var location = URI.create(response.headers("http://example.com").get("Location"));
            assertEquals("example.com", location.getHost());
            var queryMap =
                    Arrays.stream(location.getQuery().split("&"))
                            .collect(
                                    Collectors.toMap(
                                            kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
            assertEquals("xyz", queryMap.get("state"));
            assertEquals("unsupported_response_type", queryMap.get("error"));
        }
    }

    @Test
    void authorizationCodeGrant() {
        // setup
        var clientStore = new InMemoryClientStore();
        var client =
                new Client(
                        "client1",
                        "clientSecret",
                        Set.of("http://example.com"),
                        Set.of(GrantType.authorization_code),
                        Set.of(ResponseType.code),
                        "scope1 scope2");
        clientStore.save(client);
        var config = new AzIdPConfig("issuer", "kid", 3600);
        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeStore(),
                        new AccessTokenIssuer(config, new JWKSet()),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .redirectUri("http://example.com")
                        .scope("scope1")
                        .sub("username")
                        .state("xyz")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.status, 302);
        var location = response.headers("http://example.com").get("Location");
        var queryMap =
                Arrays.stream(URI.create(location).getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(queryMap.get("state"), "xyz");
        assertNotNull(queryMap.get("code"));
    }

    @Test
    void implicitGrant() throws JOSEException, ParseException {
        // setup
        var clientStore = new InMemoryClientStore();
        var client =
                new Client(
                        "client1",
                        "clientSecret",
                        Set.of("http://example.com"),
                        Set.of(GrantType.implicit),
                        Set.of(ResponseType.token),
                        "scope1 scope2");
        clientStore.save(client);
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var config = new AzIdPConfig("az.example.com", key.getKeyID(), 3600);
        var sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeStore(),
                        new AccessTokenIssuer(config, jwks),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token")
                        .clientId(client.clientId)
                        .redirectUri("http://example.com")
                        .scope("scope1")
                        .audiences(Set.of("http://rs.example.com"))
                        .sub("username")
                        .state("xyz")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.status, 302);
        var location = response.headers("http://example.com").get("Location");
        var fragmentMap =
                Arrays.stream(URI.create(location).getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(fragmentMap.get("state"), "xyz");
        var accessToken = fragmentMap.get("access_token");
        var parsedAccessToken = JWSObject.parse((String) accessToken);
        // verify signature
        assertTrue(parsedAccessToken.verify(new ECDSAVerifier(key)));
        assertEquals(parsedAccessToken.getHeader().getAlgorithm(), JWSAlgorithm.ES256);
        assertEquals(parsedAccessToken.getHeader().getType().getType(), "at+JWT");
        // verify claims
        var payload = parsedAccessToken.getPayload().toJSONObject();
        assertEquals(payload.get("sub"), "username");
        assertEquals(payload.get("aud"), List.of("http://rs.example.com"));
        assertEquals(payload.get("client_id"), "client1");
        assertEquals(payload.get("scope"), "scope1");
        assertNotNull(payload.get("jti"));
        assertEquals(payload.get("iss"), "az.example.com");
        assertTrue(
                (long) Integer.parseInt(payload.get("exp").toString())
                        > Instant.now().getEpochSecond() + 3590);
        assertTrue(
                (long) Integer.parseInt(payload.get("exp").toString())
                        < Instant.now().getEpochSecond() + 3610);
        assertTrue(
                (long) Integer.parseInt(payload.get("iat").toString())
                        > Instant.now().getEpochSecond() - 10);
        assertTrue(
                (long) Integer.parseInt(payload.get("iat").toString())
                        < Instant.now().getEpochSecond() + 10);
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in").toString()), 3600);
    }
}
