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
import org.azidp4j.token.TokenRequest;
import org.junit.jupiter.api.Test;

public class SimpleTest {

    @Test
    void test() throws JOSEException, ParseException {
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var sut =
                new AzIdP(
                        new AzIdPConfig("issuer", key.getKeyID(), 3600),
                        jwks,
                        new InMemoryClientStore());

        // client registration
        var clientRegistrationRequest =
                ClientRegistrationRequest.builder()
                        .redirectUris(Set.of("http://example.com"))
                        .grantTypes(Set.of(GrantType.authorization_code))
                        .responseTypes(Set.of(ResponseType.code))
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
        var authorizationRequest = new AuthorizationRequest("username", null, queryParameters);

        // exercise
        var authorizationResponse = sut.authorize(authorizationRequest);

        // verify
        var location = authorizationResponse.headers("http://example.com").get("Location");
        var queryMap =
                Arrays.stream(URI.create(location).getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals(queryMap.get("state"), "xyz");

        // token request
        var body =
                Map.of(
                        "code",
                        queryMap.get("code"),
                        "redirect_uri",
                        redirectUri,
                        "grant_type",
                        "authorization_code");
        var tokenRequest = new TokenRequest(clientId, Set.of("http://rs.example.com"), body);

        // exercise
        var tokenResponse = sut.issueToken(tokenRequest);

        // verify
        var accessToken = tokenResponse.body.get("access_token");
        var tokenType = tokenResponse.body.get("token_type");
        var expiresIn = tokenResponse.body.get("expires_in");
        var refreshToken = tokenResponse.body.get("refresh_token");
        System.out.println(tokenResponse.body);

        // verify signature
        var parsedAccessToken = JWSObject.parse((String) accessToken);
        var publicKey =
                jwks.toPublicJWKSet().getKeyByKeyId(parsedAccessToken.getHeader().getKeyID());
        System.out.println(publicKey);
        var jwsVerifier = new ECDSAVerifier((ECKey) publicKey);
        assertTrue(parsedAccessToken.verify(jwsVerifier));

        // verify access token
        assertEquals(parsedAccessToken.getPayload().toJSONObject().get("sub"), "username");
    }
}
