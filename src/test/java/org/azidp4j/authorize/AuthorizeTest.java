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
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.accesstoken.AccessTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.junit.jupiter.api.Test;

class AuthorizeTest {

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

    public AuthorizeTest() {
        clientStore.save(client);
        clientStore.save(noGrantTypesClient);
        clientStore.save(noResponseTypesClient);
    }

    @Test
    void additionalPage() {

        // user not login
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("scope1")
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(AdditionalPage.login, response.additionalPage);
        }
        // no consented scope
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("scope1")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of())
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(AdditionalPage.consent, response.additionalPage);
        }
        // no enough scope consented
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("scope1 scope2")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of("scope1"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(AdditionalPage.consent, response.additionalPage);
        }
        // prompt is login
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("scope1 scope2")
                            .prompt("login")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of("scope1 scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(AdditionalPage.login, response.additionalPage);
        }
        // prompt is consent(authenticated)
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("scope1 scope2")
                            .prompt("consent")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of("scope1 scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(AdditionalPage.consent, response.additionalPage);
        }
        // prompt is consent(not authenticated)
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("scope1 scope2")
                            .prompt("consent")
                            .consentedScope(Set.of("scope1 scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(AdditionalPage.login, response.additionalPage);
        }
        // prompt is login and consent
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("scope1 scope2")
                            .prompt("login consent")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of("scope1 scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(AdditionalPage.login, response.additionalPage);
        }
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
                        "rs:scope1 rs:scope2");
        clientStore.save(client);
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var config =
                new AzIdPConfig(
                        "az.example.com", key.getKeyID(), key.getKeyID(), 3600, 604800, 3600);
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
        var location = response.headers("http://rp1.example.com").get("Location");
        var fragmentMap =
                Arrays.stream(URI.create(location).getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertNull(fragmentMap.get("state"));
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
        assertEquals(payload.get("scope"), "rs:scope1");
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
                        "rs:scope1 rs:scope2");
        clientStore.save(client);
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var config =
                new AzIdPConfig(
                        "az.example.com", key.getKeyID(), key.getKeyID(), 3600, 604800, 3600);
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
        var location = response.headers("http://rp1.example.com").get("Location");
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
        assertEquals(payload.get("scope"), "rs:scope1");
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
                        Set.of(ResponseType.token),
                        "openid rs:scope1 rs:scope2");
        clientStore.save(client);
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var config =
                new AzIdPConfig(
                        "az.example.com", key.getKeyID(), key.getKeyID(), 3600, 604800, 3600);
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
                        .scope("openid rs:scope1")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("openid", "rs:scope1", "rs:scope2"))
                        .state("xyz")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.status, 302);
        var location = response.headers("http://rp1.example.com").get("Location");
        var fragmentMap =
                Arrays.stream(URI.create(location).getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(fragmentMap.get("state"), "xyz");

        // access token
        {
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
            assertEquals(payload.get("scope"), "openid rs:scope1");
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
            assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
        }

        // TODO after support multiple response type
        //        // id token
        //        {
        //            var idToken = fragmentMap.get("id_token");
        //            var parsedIdToken = JWSObject.parse(idToken);
        //            // verify signature
        //            assertTrue(parsedIdToken.verify(new ECDSAVerifier(key)));
        //            assertEquals(parsedIdToken.getHeader().getAlgorithm(), JWSAlgorithm.ES256);
        //            // verify claims
        //            var payload = parsedIdToken.getPayload().toJSONObject();
        //            assertEquals(payload.get("sub"), "username");
        //            assertEquals(payload.get("aud"), "clientId");
        //            assertNotNull(payload.get("jti"));
        //            assertEquals(payload.get("iss"), "as.example.com");
        //            assertTrue((long) payload.get("exp") > Instant.now().getEpochSecond() + 3590);
        //            assertTrue((long) payload.get("exp") < Instant.now().getEpochSecond() + 3610);
        //            assertTrue((long) payload.get("iat") > Instant.now().getEpochSecond() - 10);
        //            assertTrue((long) payload.get("iat") < Instant.now().getEpochSecond() + 10);
        //            assertNull(payload.get("nonce"));
        //            assertTrue((long) payload.get("auth_time") > Instant.now().getEpochSecond() -
        // 10);
        //            assertTrue((long) payload.get("auth_time") < Instant.now().getEpochSecond() +
        // 10);
        //            assertNotNull(payload.get("at_hash"));
        //        }
    }
}
