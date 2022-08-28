package org.azidp4j.oauth2;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.azidp4j.AzIdP;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.AuthorizationRequest;
import org.azidp4j.token.TokenRequest;
import org.junit.jupiter.api.Test;

import java.security.interfaces.ECPublicKey;
import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SimpleTest {

    @Test
    void test() throws JOSEException, ParseException {
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var sut = new AzIdP(new AzIdPConfig(key.getKeyID()), jwks);

        // authorization request
        var clientId = "sample";
        var redirectUri = "http://example.com";
        var authorizationRequest = AuthorizationRequest.builder()
                .clientId(clientId).redirectUri(redirectUri).responseType("code").scope("scope1 scope2").state("xyz").build();
        // exercise
        var authorizationResponse = sut.authorize(authorizationRequest);
        // verify
        assertEquals(authorizationResponse.query.get("state"), "xyz");

        // token request
        var code = authorizationResponse.query.get("code");
        var tokenRequest = TokenRequest.builder().clientId(clientId).redirectUri(redirectUri).grantType("authorization_code").code(code).build();
        // exercise
        var tokenResponse = sut.issueToken(tokenRequest);

        // verify
        var accessToken = tokenResponse.body.get("access_token");
        var tokenType = tokenResponse.body.get("token_type");
        var expiresIn = tokenResponse.body.get("expires_in");
        var refreshToken = tokenResponse.body.get("refresh_token");
        System.out.println(tokenResponse.body);

        // verify signature
        var parsedAccessToken = JWSObject.parse((String)accessToken);
        var publicKey = jwks.toPublicJWKSet().getKeyByKeyId(parsedAccessToken.getHeader().getKeyID());
        System.out.println(publicKey);
        var jwsVerifier = new ECDSAVerifier((ECKey) publicKey);
        assertTrue(parsedAccessToken.verify(jwsVerifier));

    }
}
