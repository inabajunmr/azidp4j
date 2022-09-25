package org.azidp4j.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.AuthorizationCodeStore;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.scope.ScopeValidator;
import org.azidp4j.token.accesstoken.AccessTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.refreshtoken.RefreshTokenIssuer;
import org.azidp4j.util.MapUtil;

public class IssueToken {

    AuthorizationCodeStore authorizationCodeStore;
    AccessTokenIssuer accessTokenIssuer;
    IDTokenIssuer idTokenIssuer;
    RefreshTokenIssuer refreshTokenIssuer;
    AzIdPConfig config;
    UserPasswordVerifier userPasswordVerifier;
    ClientStore clientStore;
    ScopeValidator scopeValidator = new ScopeValidator();
    JWKSet jwkSet;

    public IssueToken(
            AzIdPConfig azIdPConfig,
            AuthorizationCodeStore authorizationCodeStore,
            AccessTokenIssuer accessTokenIssuer,
            IDTokenIssuer idTokenIssuer,
            RefreshTokenIssuer refreshTokenIssuer,
            UserPasswordVerifier userPasswordVerifier,
            ClientStore clientStore,
            JWKSet jwkSet) {
        this.authorizationCodeStore = authorizationCodeStore;
        this.accessTokenIssuer = accessTokenIssuer;
        this.idTokenIssuer = idTokenIssuer;
        this.refreshTokenIssuer = refreshTokenIssuer;
        this.config = azIdPConfig;
        this.userPasswordVerifier = userPasswordVerifier;
        this.clientStore = clientStore;
        this.jwkSet = jwkSet;
    }

    public TokenResponse issue(InternalTokenRequest request) {
        var grantType = GrantType.of(request.grantType);
        if (request.authenticatedClientId == null && request.clientId == null) {
            return new TokenResponse(400, Map.of("error", "invalid_request"));
        }
        if (request.authenticatedClientId != null
                && request.clientId != null
                && !Objects.equals(request.authenticatedClientId, request.clientId)) {
            return new TokenResponse(400, Map.of("error", "invalid_request"));
        }
        var client =
                clientStore.find(
                        request.clientId != null
                                ? request.clientId
                                : request.authenticatedClientId);
        if (client == null) {
            return new TokenResponse(400, Map.of("error", "unauthorized_client"));
        }
        if (client.tokenEndpointAuthMethod != TokenEndpointAuthMethod.none
                && request.authenticatedClientId == null) {
            // client authentication required
            return new TokenResponse(400, Map.of("error", "invalid_client"));
        }
        if (!client.grantTypes.contains(grantType)) {
            return new TokenResponse(400, Map.of("error", "unsupported_grant_type"));
        }
        switch (grantType) {
            case authorization_code -> {
                var authorizationCode = authorizationCodeStore.consume(request.code);
                if (authorizationCode == null) {
                    return new TokenResponse(400, Map.of("error", "invalid_grant"));
                }
                if (!authorizationCode.clientId.equals(client.clientId)) {
                    return new TokenResponse(400, Map.of("error", "invalid_grant"));
                }
                // verify scope
                if (!scopeValidator.hasEnoughScope(authorizationCode.scope, client)) {
                    return new TokenResponse(400, Map.of("error", "invalid_scope"));
                }
                if (!authorizationCode.redirectUri.equals(request.redirectUri)) {
                    return new TokenResponse(400, Map.of("error", "invalid_grant"));
                }
                if (authorizationCode.codeChallengeMethod != null) {
                    switch (authorizationCode.codeChallengeMethod) {
                        case PLAIN -> {
                            if (!authorizationCode.codeChallenge.equals(request.codeVerifier)) {
                                return new TokenResponse(400, Map.of("error", "invalid_grant"));
                            }
                        }
                        case S256 -> {
                            MessageDigest sha256;
                            try {
                                sha256 = MessageDigest.getInstance("SHA-256");
                            } catch (NoSuchAlgorithmException e) {
                                throw new AssertionError();
                            }
                            var hash = sha256.digest(request.codeVerifier.getBytes());
                            if (!authorizationCode.codeChallenge.equals(
                                    Base64URL.encode(hash).toString())) {
                                return new TokenResponse(400, Map.of("error", "invalid_grant"));
                            }
                        }
                        default -> throw new AssertionError();
                    }
                }
                var at =
                        accessTokenIssuer.issue(
                                authorizationCode.sub, client.clientId, authorizationCode.scope);
                var rt =
                        refreshTokenIssuer.issue(
                                authorizationCode.sub, client.clientId, authorizationCode.scope);
                if (scopeValidator.contains(authorizationCode.scope, "openid")) {
                    // OIDC
                    var idToken =
                            idTokenIssuer.issue(
                                    authorizationCode.sub,
                                    client.clientId,
                                    authorizationCode.authTime,
                                    authorizationCode.nonce,
                                    at.serialize(),
                                    null);
                    if (authorizationCode.state == null) {
                        return new TokenResponse(
                                200,
                                MapUtil.nullRemovedMap(
                                        "access_token",
                                        at.serialize(),
                                        "id_token",
                                        idToken.serialize(),
                                        "refresh_token",
                                        rt.serialize(),
                                        "token_type",
                                        "bearer",
                                        "expires_in",
                                        config.accessTokenExpirationSec,
                                        "scope",
                                        authorizationCode.scope));
                    }
                    return new TokenResponse(
                            200,
                            MapUtil.nullRemovedMap(
                                    "access_token",
                                    at.serialize(),
                                    "id_token",
                                    idToken.serialize(),
                                    "refresh_token",
                                    rt.serialize(),
                                    "token_type",
                                    "bearer",
                                    "expires_in",
                                    config.accessTokenExpirationSec,
                                    "scope",
                                    authorizationCode.scope,
                                    "state",
                                    authorizationCode.state));

                } else {
                    // OAuth2.0
                    return new TokenResponse(
                            200,
                            MapUtil.nullRemovedMap(
                                    "access_token",
                                    at.serialize(),
                                    "refresh_token",
                                    rt.serialize(),
                                    "token_type",
                                    "bearer",
                                    "expires_in",
                                    config.accessTokenExpirationSec,
                                    "scope",
                                    authorizationCode.scope,
                                    "state",
                                    authorizationCode.state));
                }
            }
            case password -> {
                // verify scope
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
                    var at =
                            accessTokenIssuer.issue(
                                    request.username, client.clientId, request.scope);
                    var rt =
                            refreshTokenIssuer.issue(
                                    request.username, client.clientId, request.scope);
                    return new TokenResponse(
                            200,
                            MapUtil.nullRemovedMap(
                                    "access_token",
                                    at.serialize(),
                                    "refresh_token",
                                    rt.serialize(),
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
            case client_credentials -> {
                if (client.tokenEndpointAuthMethod == TokenEndpointAuthMethod.none) {
                    return new TokenResponse(400, Map.of("error", "invalid_client"));
                }
                // verify scope
                if (!scopeValidator.hasEnoughScope(request.scope, client)) {
                    return new TokenResponse(400, Map.of("error", "invalid_scope"));
                }
                var jws = accessTokenIssuer.issue(client.clientId, client.clientId, request.scope);
                return new TokenResponse(
                        200,
                        MapUtil.nullRemovedMap(
                                "access_token",
                                jws.serialize(),
                                "token_type",
                                "bearer",
                                "expires_in",
                                config.accessTokenExpirationSec,
                                "scope",
                                request.scope));
            }
            case refresh_token -> {
                try {
                    var requestedRt = JWSObject.parse(request.refreshToken);
                    var key = (ECKey) jwkSet.getKeyByKeyId(requestedRt.getHeader().getKeyID());
                    var verifier = new ECDSAVerifier(key);
                    if (!requestedRt.verify(verifier)) {
                        return new TokenResponse(400, Map.of("error", "invalid_grant"));
                    }
                    var parsedRt = requestedRt.getPayload().toJSONObject();
                    if (!parsedRt.get("iss").equals(config.issuer)) {
                        return new TokenResponse(400, Map.of("error", "invalid_grant"));
                    }
                    if (!parsedRt.get("client_id").equals(client.clientId)) {
                        return new TokenResponse(400, Map.of("error", "invalid_grant"));
                    }
                    if ((long) parsedRt.get("exp") < Instant.now().getEpochSecond()) {
                        return new TokenResponse(400, Map.of("error", "invalid_grant"));
                    }
                    if (!scopeValidator.hasEnoughScope(
                            request.scope, (String) parsedRt.get("scope"))) {
                        return new TokenResponse(400, Map.of("error", "invalid_scope"));
                    }
                    var scope =
                            request.scope != null ? request.scope : (String) parsedRt.get("scope");
                    var at =
                            accessTokenIssuer.issue(
                                    (String) parsedRt.get("sub"), client.clientId, scope);
                    var rt =
                            refreshTokenIssuer.issue(
                                    (String) parsedRt.get("sub"), client.clientId, scope);
                    return new TokenResponse(
                            200,
                            MapUtil.nullRemovedMap(
                                    "access_token",
                                    at.serialize(),
                                    "refresh_token",
                                    rt.serialize(),
                                    "token_type",
                                    "bearer",
                                    "expires_in",
                                    config.accessTokenExpirationSec,
                                    "scope",
                                    scope));
                } catch (ParseException | IllegalStateException e) {
                    return new TokenResponse(400, Map.of("error", "invalid_grant"));
                } catch (JOSEException e) {
                    throw new AssertionError("JWKs is something wrong.");
                }
            }
            default -> {
                throw new RuntimeException("unsupported grant type");
            }
        }
    }
}
