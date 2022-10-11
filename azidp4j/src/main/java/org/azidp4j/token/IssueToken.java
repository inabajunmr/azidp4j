package org.azidp4j.token;

import com.nimbusds.jose.util.Base64URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.AuthorizationCodeStore;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.scope.ScopeValidator;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.accesstoken.AccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.refreshtoken.RefreshToken;
import org.azidp4j.token.refreshtoken.RefreshTokenStore;
import org.azidp4j.util.MapUtil;

public class IssueToken {

    private final AuthorizationCodeStore authorizationCodeStore;
    private final AccessTokenStore accessTokenStore;
    private final AccessTokenService accessTokenService;
    private final ScopeAudienceMapper scopeAudienceMapper;
    private final IDTokenIssuer idTokenIssuer;
    private final RefreshTokenStore refreshTokenStore;
    private final AzIdPConfig config;
    private final UserPasswordVerifier userPasswordVerifier;
    private final ClientStore clientStore;
    private final ScopeValidator scopeValidator = new ScopeValidator();

    public IssueToken(
            AzIdPConfig azIdPConfig,
            AuthorizationCodeStore authorizationCodeStore,
            AccessTokenService accessTokenService,
            AccessTokenStore accessTokenStore,
            IDTokenIssuer idTokenIssuer,
            RefreshTokenStore refreshTokenStore,
            ScopeAudienceMapper scopeAudienceMapper,
            UserPasswordVerifier userPasswordVerifier,
            ClientStore clientStore) {
        this.authorizationCodeStore = authorizationCodeStore;
        this.accessTokenService = accessTokenService;
        this.accessTokenStore = accessTokenStore;
        this.idTokenIssuer = idTokenIssuer;
        this.refreshTokenStore = refreshTokenStore;
        this.scopeAudienceMapper = scopeAudienceMapper;
        this.config = azIdPConfig;
        this.userPasswordVerifier = userPasswordVerifier;
        this.clientStore = clientStore;
    }

    public TokenResponse issue(InternalTokenRequest request) {
        var grantType = GrantType.of(request.grantType);
        if (grantType == null) {
            return new TokenResponse(400, Map.of("error", "invalid_request"));
        }
        if (request.authenticatedClientId == null && request.clientId == null) {
            return new TokenResponse(400, Map.of("error", "invalid_request"));
        }
        if (request.authenticatedClientId != null
                && request.clientId != null
                && !Objects.equals(request.authenticatedClientId, request.clientId)) {
            return new TokenResponse(400, Map.of("error", "invalid_request"));
        }
        var clientOpt =
                clientStore.find(
                        request.clientId != null
                                ? request.clientId
                                : request.authenticatedClientId);
        if (!clientOpt.isPresent()) {
            return new TokenResponse(400, Map.of("error", "unauthorized_client"));
        }
        var client = clientOpt.get();
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
                var authorizationCodeOpt = authorizationCodeStore.consume(request.code);
                if (!authorizationCodeOpt.isPresent()) {
                    accessTokenStore.removeByAuthorizationCode(request.code);
                    refreshTokenStore.removeByAuthorizationCode(request.code);
                    return new TokenResponse(400, Map.of("error", "invalid_grant"));
                }
                var authorizationCode = authorizationCodeOpt.get();
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
                if (authorizationCode.expiresAtEpochSec <= Instant.now().getEpochSecond()) {
                    return new TokenResponse(400, Map.of("error", "invalid_grant"));
                }

                var at =
                        accessTokenService.issue(
                                authorizationCode.sub,
                                authorizationCode.scope,
                                authorizationCode.clientId,
                                authorizationCode.code);
                var rt =
                        new RefreshToken(
                                UUID.randomUUID().toString(),
                                authorizationCode.sub,
                                authorizationCode.scope,
                                authorizationCode.clientId,
                                scopeAudienceMapper.map(authorizationCode.scope),
                                Instant.now().getEpochSecond() + config.refreshTokenExpirationSec,
                                Instant.now().getEpochSecond());
                refreshTokenStore.save(rt);
                if (scopeValidator.contains(authorizationCode.scope, "openid")) {
                    // OIDC
                    var idToken =
                            idTokenIssuer.issue(
                                    authorizationCode.sub,
                                    client.clientId,
                                    authorizationCode.authTime,
                                    authorizationCode.nonce,
                                    at.getToken(),
                                    null,
                                    client.idTokenSignedResponseAlg);
                    if (authorizationCode.state == null) {
                        return new TokenResponse(
                                200,
                                MapUtil.nullRemovedMap(
                                        "access_token",
                                        at.getToken(),
                                        "id_token",
                                        idToken.serialize(),
                                        "refresh_token",
                                        rt.token,
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
                                    at.getToken(),
                                    "id_token",
                                    idToken.serialize(),
                                    "refresh_token",
                                    rt.token,
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
                                    at.getToken(),
                                    "refresh_token",
                                    rt.token,
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
                // TODO scope is required
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
                            accessTokenService.issue(
                                    request.username, request.scope, client.clientId);
                    var rt =
                            new RefreshToken(
                                    UUID.randomUUID().toString(),
                                    request.username,
                                    request.scope,
                                    client.clientId,
                                    scopeAudienceMapper.map(request.scope),
                                    Instant.now().getEpochSecond()
                                            + config.refreshTokenExpirationSec,
                                    Instant.now().getEpochSecond());
                    return new TokenResponse(
                            200,
                            MapUtil.nullRemovedMap(
                                    "access_token",
                                    at.getToken(),
                                    "refresh_token",
                                    rt.token,
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
                if (request.scope == null) {
                    return new TokenResponse(400, Map.of("error", "invalid_scope"));
                }
                if (client.tokenEndpointAuthMethod == TokenEndpointAuthMethod.none) {
                    return new TokenResponse(400, Map.of("error", "invalid_client"));
                }
                // verify scope
                if (!scopeValidator.hasEnoughScope(request.scope, client)) {
                    return new TokenResponse(400, Map.of("error", "invalid_scope"));
                }
                var at = accessTokenService.issue(client.clientId, request.scope, client.clientId);
                return new TokenResponse(
                        200,
                        MapUtil.nullRemovedMap(
                                "access_token",
                                at.getToken(),
                                "token_type",
                                "bearer",
                                "expires_in",
                                config.accessTokenExpirationSec,
                                "scope",
                                request.scope));
            }
            case refresh_token -> {
                if (request.refreshToken == null) {
                    return new TokenResponse(400, Map.of("error", "invalid_grant"));
                }
                var rtOpt = refreshTokenStore.consume(request.refreshToken);
                if (!rtOpt.isPresent()) {
                    return new TokenResponse(400, Map.of("error", "invalid_grant"));
                }
                var rt = rtOpt.get();
                if (!rt.clientId.equals(client.clientId)) {
                    return new TokenResponse(400, Map.of("error", "invalid_grant"));
                }
                if (rt.expiresAtEpochSec < Instant.now().getEpochSecond()) {
                    return new TokenResponse(400, Map.of("error", "invalid_grant"));
                }
                if (!scopeValidator.hasEnoughScope(request.scope, rt.scope)) {
                    return new TokenResponse(400, Map.of("error", "invalid_scope"));
                }
                var scope = request.scope != null ? request.scope : rt.scope;
                var at =
                        accessTokenService.issue(
                                rt.sub, scope, client.clientId, rt.authorizationCode);
                var newRt =
                        new RefreshToken(
                                UUID.randomUUID().toString(),
                                rt.sub,
                                scope,
                                rt.clientId,
                                scopeAudienceMapper.map(scope),
                                Instant.now().getEpochSecond() + config.refreshTokenExpirationSec,
                                Instant.now().getEpochSecond(),
                                rt.authorizationCode);
                refreshTokenStore.save(newRt);
                return new TokenResponse(
                        200,
                        MapUtil.nullRemovedMap(
                                "access_token",
                                at.getToken(),
                                "refresh_token",
                                newRt.token,
                                "token_type",
                                "bearer",
                                "expires_in",
                                config.accessTokenExpirationSec,
                                "scope",
                                scope));
            }
            default -> throw new RuntimeException("unsupported grant type");
        }
    }
}
