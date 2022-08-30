package org.azidp4j.token;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.text.ParseException;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.AuthorizationCode;
import org.azidp4j.authorize.InMemoryAuthorizationCodeStore;
import org.junit.jupiter.api.Test;

class IssueTokenTest_AuthorizationCodeGrant {

    @Test
    void success() throws JOSEException, ParseException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                new AuthorizationCode(
                        subject, UUID.randomUUID().toString(), "scope1", "clientId", "xyz");
        authorizationCodeStore.save(authorizationCode);
        var accessTokenStore = new InMemoryAccessTokenStore();
        var issueToken =
                new IssueToken(
                        new AzIdPConfig("example.com", key.getKeyID()),
                        jwks,
                        authorizationCodeStore,
                        accessTokenStore);
        var tokenRequest =
                TokenRequest.builder()
                        .code(authorizationCode.code)
                        .grantType("authorization_code")
                        .redirectUri("http://example.com")
                        .clientId("clientId")
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
        // verify claims
        var payload = parsedAccessToken.getPayload().toJSONObject();
        assertEquals(payload.get("sub"), subject);
        assertEquals(payload.get("aud"), List.of("http://rs.example.com"));
        assertEquals(payload.get("client_id"), "clientId");
        assertEquals(payload.get("scope"), "scope1");
        assertNotNull(payload.get("jti"));
        // TODO iss/exp/iat
        response.body.get("token_type");
        response.body.get("expires_in");
        // response.body.get("refresh_token");
        response.body.get("scope");
    }
}
