package org.azidp4j.token;

import java.util.Map;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.AuthorizationCodeStore;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.scope.ScopeValidator;

public class IssueToken {

    AuthorizationCodeStore authorizationCodeStore;
    AccessTokenStore accessTokenStore;
    AccessTokenIssuer accessTokenIssuer;
    AzIdPConfig config;
    UserPasswordVerifier userPasswordVerifier;
    ClientStore clientStore;
    ScopeValidator scopeValidator = new ScopeValidator();

    public IssueToken(
            AzIdPConfig azIdPConfig,
            AuthorizationCodeStore authorizationCodeStore,
            AccessTokenStore accessTokenStore,
            AccessTokenIssuer accessTokenIssuer,
            UserPasswordVerifier userPasswordVerifier,
            ClientStore clientStore) {
        this.authorizationCodeStore = authorizationCodeStore;
        this.accessTokenStore = accessTokenStore;
        this.accessTokenIssuer = accessTokenIssuer;
        this.config = azIdPConfig;
        this.userPasswordVerifier = userPasswordVerifier;
        this.clientStore = clientStore;
    }

    public TokenResponse issue(InternalTokenRequest request) {
        var grantType = GrantType.of(request.grantType);
        var client = clientStore.find(request.clientId);
        if (client == null) {
            return new TokenResponse(400, Map.of("error", "unauthorized_client"));
        }
        if (!client.grantTypes.contains(grantType)) { // TODO test
            return new TokenResponse(400, Map.of("error", "unsupported_grant_type"));
        }
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
                    // verify scope // TODO test
                    if (!scopeValidator.hasEnoughScope(request.scope, client)) {
                        return new TokenResponse(400, Map.of("error", "invalid_scope"));
                    }
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
                    // verify scope // TODO test
                    if (!scopeValidator.hasEnoughScope(request.scope, client)) {
                        return new TokenResponse(400, Map.of("error", "invalid_scope"));
                    }
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
