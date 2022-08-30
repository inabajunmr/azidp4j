package org.azidp4j.token;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.Map;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.AuthorizationCodeStore;
import org.azidp4j.client.GrantType;

public class IssueToken {

    AuthorizationCodeStore authorizationCodeStore;
    AccessTokenStore accessTokenStore;
    AccessTokenIssuer accessTokenIssuer;
    AzIdPConfig config;

    public IssueToken(
            AzIdPConfig azIdPConfig,
            JWKSet jwkSet,
            AuthorizationCodeStore authorizationCodeStore,
            AccessTokenStore accessTokenStore) {
        this.authorizationCodeStore = authorizationCodeStore;
        this.accessTokenStore = accessTokenStore;
        this.accessTokenIssuer = new AccessTokenIssuer(azIdPConfig, jwkSet);
        this.config = azIdPConfig;
    }

    public TokenResponse issue(TokenRequest request) {
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
            case client_credentials:
                {
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
