package org.azidp4j.token.request;

import org.azidp4j.RequestParserUtil;

public class TokenRequestParser {
    public InternalTokenRequest parse(TokenRequest tokenRequest) {

        var code = RequestParserUtil.valueToString("code", tokenRequest.bodyParameters);
        var grantType = RequestParserUtil.valueToString("grant_type", tokenRequest.bodyParameters);
        var redirectUri =
                RequestParserUtil.valueToString("redirect_uri", tokenRequest.bodyParameters);
        var scope = RequestParserUtil.valueToString("scope", tokenRequest.bodyParameters);
        var authenticatedClientId = tokenRequest.authenticatedClientId;
        var clientId = RequestParserUtil.valueToString("client_id", tokenRequest.bodyParameters);
        var username = RequestParserUtil.valueToString("username", tokenRequest.bodyParameters);
        var password = RequestParserUtil.valueToString("password", tokenRequest.bodyParameters);
        var refreshToken =
                RequestParserUtil.valueToString("refresh_token", tokenRequest.bodyParameters);
        var codeVerifier =
                RequestParserUtil.valueToString("code_verifier", tokenRequest.bodyParameters);
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
