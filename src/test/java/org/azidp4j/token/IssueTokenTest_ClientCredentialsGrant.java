package org.azidp4j.token;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.InMemoryAuthorizationCodeStore;
import org.azidp4j.client.Client;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.InMemoryClientStore;
import org.junit.jupiter.api.Test;

class IssueTokenTest_ClientCredentialsGrant {

    @Test
    void success() throws JOSEException, ParseException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var accessTokenStore = new InMemoryAccessTokenStore();
        var config = new AzIdPConfig("as.example.com", key.getKeyID(), 3600);
        var accessTokenIssuer = new AccessTokenIssuer(config, jwks);
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.client_credentials),
                        Set.of(),
                        "scope1 scope2"));
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        accessTokenStore,
                        accessTokenIssuer,
                        null,
                        clientStore);
        var tokenRequest =
                InternalTokenRequest.builder()
                        .grantType("client_credentials")
                        .clientId("clientId")
                        .scope("scope1")
                        .audiences(Set.of("http://rs.example.com"))
                        .build();

        // exercise
        var response = issueToken.issue(tokenRequest);

        // verify
        assertEquals(response.status, 200);
        // access token
        var accessToken = response.body.get("access_token");
        var parsedAccessToken = JWSObject.parse((String) accessToken);
        // verify signature
        assertTrue(parsedAccessToken.verify(new ECDSAVerifier(key)));
        assertEquals(parsedAccessToken.getHeader().getAlgorithm(), JWSAlgorithm.ES256);
        assertEquals(parsedAccessToken.getHeader().getType().getType(), "at+JWT");
        // verify claims
        var payload = parsedAccessToken.getPayload().toJSONObject();
        assertEquals(payload.get("sub"), "clientId");
        assertEquals(payload.get("aud"), List.of("http://rs.example.com"));
        assertEquals(payload.get("client_id"), "clientId");
        assertEquals(payload.get("scope"), "scope1");
        assertNotNull(payload.get("jti"));
        assertEquals(payload.get("iss"), "as.example.com");
        assertTrue((long) payload.get("exp") > Instant.now().getEpochSecond() + 3590);
        assertTrue((long) payload.get("exp") < Instant.now().getEpochSecond() + 3610);
        assertTrue((long) payload.get("iat") > Instant.now().getEpochSecond() - 10);
        assertTrue((long) payload.get("iat") < Instant.now().getEpochSecond() + 10);
        assertEquals(response.body.get("token_type"), "bearer");
        assertEquals(response.body.get("expires_in"), 3600);
        assertFalse(response.body.containsKey("refresh_token"));
    }
}
