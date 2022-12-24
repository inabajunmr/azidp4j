package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AccessTokenAssert;
import org.azidp4j.Fixtures;
import org.azidp4j.IdTokenAssert;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeStore;
import org.azidp4j.authorize.request.InternalAuthorizationRequest;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.authorize.response.NextAction;
import org.azidp4j.client.*;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.SampleIdTokenKidSupplier;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenClaimsAssembler;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenValidator;
import org.junit.jupiter.api.Test;

class AuthorizeTest_Implicit_IDTokenClaimsAssembler {

    final IDTokenClaimsAssembler idTokenClaimsAssembler =
            (sub, scope) -> Map.of("key1", "value1", "key2", Map.of("key2-1", "value2-1"));

    final ClientStore clientStore = new InMemoryClientStore();
    final ECKey eckey =
            new ECKeyGenerator(Curve.P_256)
                    .algorithm(new Algorithm("ES256"))
                    .keyID("123")
                    .generate();
    final RSAKey rsaKey =
            new RSAKeyGenerator(2048).keyID("abc").algorithm(new Algorithm("RS256")).generate();

    final Client clientEs256 =
            new Client(
                    "es256client",
                    "clientSecret",
                    Set.of("http://rp1.example.com", "http://rp2.example.com"),
                    Set.of(
                            Set.of(ResponseType.token),
                            Set.of(ResponseType.id_token),
                            Set.of(ResponseType.token, ResponseType.id_token)),
                    ApplicationType.WEB,
                    Set.of(GrantType.authorization_code, GrantType.implicit),
                    null,
                    null,
                    null,
                    "rs:scope1 rs:scope2 openid",
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
                    null);

    final Client clientRs256 =
            new Client(
                    "rs256client",
                    "clientSecret",
                    Set.of("http://rp1.example.com", "http://rp2.example.com"),
                    Set.of(Set.of(ResponseType.token, ResponseType.id_token)),
                    ApplicationType.WEB,
                    Set.of(GrantType.implicit),
                    null,
                    null,
                    null,
                    "openid rs:scope1 rs:scope2",
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    TokenEndpointAuthMethod.client_secret_basic,
                    null,
                    SigningAlgorithm.RS256,
                    null,
                    null,
                    null);

    final Authorize sut;
    final InMemoryAccessTokenStore accessTokenStore;

    public AuthorizeTest_Implicit_IDTokenClaimsAssembler() throws JOSEException {
        var config = Fixtures.azIdPConfig();
        var scopeAudienceMapper = new SampleScopeAudienceMapper();
        this.accessTokenStore = new InMemoryAccessTokenStore();
        var jwks = new JWKSet(List.of(rsaKey, eckey));
        this.sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                        scopeAudienceMapper,
                        new InMemoryAccessTokenService(accessTokenStore),
                        new IDTokenIssuer(
                                config,
                                jwks,
                                new SampleIdTokenKidSupplier(jwks),
                                idTokenClaimsAssembler),
                        new IDTokenValidator(config, jwks),
                        config);

        clientStore.save(clientEs256);
        clientStore.save(clientRs256);
    }

    @Test
    void implicitGrant_oidc_es256_withState_tokenAndIDToken() throws JOSEException, ParseException {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token id_token")
                        .clientId(clientEs256.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("openid rs:scope1")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("openid", "rs:scope1", "rs:scope2"))
                        .state("xyz")
                        .nonce("abc")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect.redirectTo;
        var fragmentMap =
                Arrays.stream(URI.create(location).getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(fragmentMap.get("state"), "xyz");
        AccessTokenAssert.assertAccessToken(
                accessTokenStore.find(fragmentMap.get("access_token")).get(),
                "username",
                "http://rs.example.com",
                clientEs256.clientId,
                "openid rs:scope1",
                Instant.now().getEpochSecond() + 3600);
        assertEquals(fragmentMap.get("token_type"), "bearer");
        assertEquals(Integer.parseInt(fragmentMap.get("expires_in")), 3600);
        IdTokenAssert.assertIdTokenES256(
                fragmentMap.get("id_token"),
                eckey,
                "username",
                clientEs256.clientId,
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                "abc",
                fragmentMap.get("access_token"),
                null);
        // verify claims from idTokenClaimsAssembler
        var idToken = JWSObject.parse(fragmentMap.get("id_token"));
        // access token was issued so claims will be gained via userinfo endpoint
        assertNull(idToken.getPayload().toJSONObject().get("key1"));
    }

    @Test
    void implicitGrant_oidc_es256_withState_onlyIDToken() throws JOSEException, ParseException {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("id_token")
                        .clientId(clientEs256.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("openid rs:scope1")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("openid", "rs:scope1", "rs:scope2"))
                        .state("xyz")
                        .nonce("abc")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect.redirectTo;
        var fragmentMap =
                Arrays.stream(URI.create(location).getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(fragmentMap.get("state"), "xyz");
        IdTokenAssert.assertIdTokenES256(
                fragmentMap.get("id_token"),
                eckey,
                "username",
                clientEs256.clientId,
                "http://localhost:8080",
                Instant.now().getEpochSecond() + 3600,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                "abc",
                fragmentMap.get("access_token"),
                null);
        // verify claims from idTokenClaimsAssembler
        var idToken = JWSObject.parse(fragmentMap.get("id_token"));
        assertEquals("value1", idToken.getPayload().toJSONObject().get("key1"));
        assertEquals(
                "value2-1",
                ((Map<?, ?>) (idToken.getPayload().toJSONObject().get("key2"))).get("key2-1"));
    }
}
