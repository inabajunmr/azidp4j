package org.azidp4j.token;

public class TokenRequestParser {
    public InternalTokenRequest parse(TokenRequest tokenRequest) {
        var code = tokenRequest.bodyParameters.get("code");
        var grantType = tokenRequest.bodyParameters.get("grant_type");
        var redirectUri = tokenRequest.bodyParameters.get("redirect_uri");
        var scope = tokenRequest.bodyParameters.get("scope");
        var authenticatedClientId = tokenRequest.authenticatedClientId;
        var clientId = tokenRequest.bodyParameters.get("client_id");
        var username = tokenRequest.bodyParameters.get("username");
        var password = tokenRequest.bodyParameters.get("password");
        var refreshToken = tokenRequest.bodyParameters.get("refresh_token");
        var codeVerifier = tokenRequest.bodyParameters.get("code_verifier");
        return InternalTokenRequest.builder()
                .code(code)
                .grantType(grantType)
                .redirectUri(redirectUri)
                .clientId(clientId)
                .authenticatedClientId(authenticatedClientId)
                .scope(scope)
                .username(username)
                .password(password)
                .refreshToken(refreshToken)
                .codeVerifier(codeVerifier)
                .build();
    }
}
