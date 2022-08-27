package org.azidp4j.oauth2;

import org.azidp4j.AzIdP;
import org.azidp4j.authorize.AuthorizationRequest;
import org.azidp4j.authorize.AuthorizationResponse;
import org.azidp4j.token.TokenRequest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SimpleTest {

    @Test
    void test() {
        var sut = new AzIdP();

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
        var accessToken = tokenResponse.body.get("access_token");
        var tokenType = tokenResponse.body.get("token_type");
        var expiresIn = tokenResponse.body.get("expires_in");
        var refreshToken = tokenResponse.body.get("refresh_token");
        System.out.println(tokenResponse.body);

    }
}
