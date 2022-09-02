package org.azidp4j.token;

public class TokenRequestParser {
    public InternalTokenRequest parse(TokenRequest tokenRequest) {
        var code = tokenRequest.bodyParameters.get("code");
        var grantType = tokenRequest.bodyParameters.get("grant_type");
        var redirectUri = tokenRequest.bodyParameters.get("redirect_uri");
        // var clientId = bodyMap.get("client_id"); TODO for public client?
        var scope = tokenRequest.bodyParameters.get("scope");
        var clientId = tokenRequest.authenticatedClientId;
        if (tokenRequest.authenticatedClientId == null) {
            clientId = tokenRequest.bodyParameters.get("clientId");
        }
        var username = tokenRequest.bodyParameters.get("username");
        var password = tokenRequest.bodyParameters.get("password");
        var internalTokenRequest =
                InternalTokenRequest.builder()
                        .code(code)
                        .grantType(grantType)
                        .redirectUri(redirectUri)
                        .clientId(clientId)
                        .scope(scope)
                        .username(username)
                        .password(password)
                        .audiences(tokenRequest.audiences)
                        .build();
        return internalTokenRequest;
    }
}
