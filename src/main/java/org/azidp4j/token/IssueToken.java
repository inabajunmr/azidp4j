package org.azidp4j.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import org.azidp4j.authorize.AuthorizationCodeStore;
import org.azidp4j.jwt.jwks.JWKSupplier;

import java.io.File;
import java.util.Map;
import java.util.UUID;

public class IssueToken {

    AuthorizationCodeStore authorizationCodeStore;
    AccessTokenStore accessTokenStore;
    AccessTokenIssuer accessTokenIssuer;

    public IssueToken(AuthorizationCodeStore authorizationCodeStore, AccessTokenStore accessTokenStore, JWKSupplier jwkSupplier) {
        this.authorizationCodeStore = authorizationCodeStore;
        this.accessTokenStore = accessTokenStore;
        this.accessTokenIssuer = new AccessTokenIssuer(jwkSupplier);
    }

    public TokenResponse issue(TokenRequest request) {
        var authorizationCode = authorizationCodeStore.find(request.code);
        var jws = accessTokenIssuer.issue("sub", "aud", "clientId", authorizationCode.scope);
        return new TokenResponse(Map.of("access_token", jws.serialize(),
                "token_type", "bearer",
                "expires_in",3600,
                "scope", authorizationCode.scope,
                "state", authorizationCode.state));
    }
}
