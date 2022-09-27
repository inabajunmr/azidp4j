package org.azidp4j.oauth2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AzIdP;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.AuthorizationRequest;
import org.azidp4j.authorize.ResponseType;
import org.azidp4j.client.ClientRegistrationRequest;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.TokenRequest;
import org.junit.jupiter.api.Test;

public class SimpleTest {

    /**
     * 1. client registration 2. authorization request(authorization code grant) 3. token
     * request(using authorization code) 4. token request(using refresh token)
     */
    @Test
    void test() throws JOSEException, ParseException {
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var sut =
                new AzIdP(
                        new AzIdPConfig(
                                "issuer", key.getKeyID(), key.getKeyID(), 3600, 600, 604800, 3600),
                        jwks,
                        new InMemoryClientStore(),
                        new SampleScopeAudienceMapper());

        // client registration
        var clientRegistrationRequest =
                ClientRegistrationRequest.builder()
                        .redirectUris(Set.of("http://example.com"))
                        .grantTypes(
                                Set.of(
                                        GrantType.authorization_code.name(),
                                        GrantType.refresh_token.name()))
                        .responseTypes(Set.of(ResponseType.code.name()))
                        .scope("scope1 scope2")
                        .build();
        var clientRegistrationResponse = sut.registerClient(clientRegistrationRequest);
        var clientId = (String) clientRegistrationResponse.body.get("client_id");

        // authorization request
        var redirectUri = "http://example.com";
        var queryParameters =
                Map.of(
                        "client_id",
                        clientId,
                        "redirect_uri",
                        redirectUri,
                        "response_type",
                        "code",
                        "scope",
                        "scope1 scope2",
                        "state",
                        "xyz");
        var authorizationRequest =
                new AuthorizationRequest(
                        "username",
                        Instant.now().getEpochSecond(),
                        Set.of("scope1", "scope2"),
                        queryParameters);

        // exercise
        var authorizationResponse = sut.authorize(authorizationRequest);

        // verify
        var location = authorizationResponse.headers().get("Location");
        var queryMap =
                Arrays.stream(URI.create(location).getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(queryMap.get("state"), "xyz");

        // token request
        var tokenRequestBody1 =
                Map.of(
                        "code",
                        queryMap.get("code"),
                        "redirect_uri",
                        redirectUri,
                        "grant_type",
                        "authorization_code");
        var tokenRequest1 =
                new TokenRequest(clientId, Instant.now().getEpochSecond(), tokenRequestBody1);

        // exercise
        var tokenResponse1 = sut.issueToken(tokenRequest1);

        // verify
        var accessToken = tokenResponse1.body.get("access_token");
        var refreshToken = tokenResponse1.body.get("refresh_token");

        // verify signature
        var parsedAccessToken1 = JWSObject.parse((String) accessToken);
        var publicKey =
                jwks.toPublicJWKSet().getKeyByKeyId(parsedAccessToken1.getHeader().getKeyID());
        var jwsVerifier = new ECDSAVerifier((ECKey) publicKey);
        assertTrue(parsedAccessToken1.verify(jwsVerifier));

        // verify access token
        assertEquals(parsedAccessToken1.getPayload().toJSONObject().get("sub"), "username");

        // token request
        var tokenRequestBody2 =
                Map.of("refresh_token", (String) refreshToken, "grant_type", "refresh_token");
        var tokenRequest2 =
                new TokenRequest(clientId, Instant.now().getEpochSecond(), tokenRequestBody2);

        // exercise
        var tokenResponse2 = sut.issueToken(tokenRequest2);

        // verify
        var refreshedAccessToken = tokenResponse2.body.get("access_token");

        // verify signature
        var parsedAccessToken2 = JWSObject.parse((String) refreshedAccessToken);
        assertTrue(parsedAccessToken2.verify(jwsVerifier));

        // verify access token
        assertEquals(parsedAccessToken2.getPayload().toJSONObject().get("sub"), "username");
    }
}
