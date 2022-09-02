package org.azidp4j.token;

import java.util.Map;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.AuthorizationCodeStore;
import org.azidp4j.client.GrantType;

public class IssueToken {

    AuthorizationCodeStore authorizationCodeStore;
    AccessTokenStore accessTokenStore;
    AccessTokenIssuer accessTokenIssuer;
    AzIdPConfig config;
    UserPasswordVerifier userPasswordVerifier;

    public IssueToken(
            AzIdPConfig azIdPConfig,
            AuthorizationCodeStore authorizationCodeStore,
            AccessTokenStore accessTokenStore,
            AccessTokenIssuer accessTokenIssuer,
            UserPasswordVerifier userPasswordVerifier) {
        this.authorizationCodeStore = authorizationCodeStore;
        this.accessTokenStore = accessTokenStore;
        this.accessTokenIssuer = accessTokenIssuer;
        this.config = azIdPConfig;
        this.userPasswordVerifier = userPasswordVerifier;
    }

    public TokenResponse issue(InternalTokenRequest request) {
        var grantType = GrantType.of(request.grantType);
        switch (grantType) {
            case authorization_code:
                {
                    var authorizationCode = authorizationCodeStore.find(request.code);
                    var jws =
                            accessTokenIssuer.issue(
                                    authorizationCode.sub,
                                    request.audiences,
                                    request.clientId,
                                    authorizationCode.scope);
                    return new TokenResponse(
                            200,
                            Map.of(
                                    "access_token",
                                    jws.serialize(),
                                    "token_type",
                                    "bearer",
                                    "expires_in",
                                    config.accessTokenExpirationSec,
                                    "scope",
                                    authorizationCode.scope,
                                    "state",
                                    authorizationCode.state));
                }
            case password:
                {
                    // TODO verify client grant type
                    // verify user
                    if (userPasswordVerifier == null) {
                        throw new AssertionError(
                                "Resource owner password credentials grant needs to set"
                                        + " userPasswordVerifier on AzIdp instance.");
                    }
                    if (userPasswordVerifier.verify(request.username, request.password)) {
                        var jws =
                                accessTokenIssuer.issue(
                                        request.username,
                                        request.audiences,
                                        request.clientId,
                                        request.scope);
                        return new TokenResponse(
                                200,
                                Map.of(
                                        "access_token",
                                        jws.serialize(),
                                        "token_type",
                                        "bearer",
                                        "expires_in",
                                        config.accessTokenExpirationSec,
                                        "scope",
                                        request.scope));
                    } else {
                        return new TokenResponse(400, Map.of("error", "invalid_grant"));
                    }
                }
            case client_credentials:
                {
                    // TODO verify client grant type
                    var jws =
                            accessTokenIssuer.issue(
                                    request.clientId,
                                    request.audiences,
                                    request.clientId,
                                    request.scope);
                    return new TokenResponse(
                            200,
                            Map.of(
                                    "access_token",
                                    jws.serialize(),
                                    "token_type",
                                    "bearer",
                                    "expires_in",
                                    config.accessTokenExpirationSec,
                                    "scope",
                                    request.scope));
                }
            default:
                {
                    throw new RuntimeException("unsupported grant type");
                }
        }
    }
}
