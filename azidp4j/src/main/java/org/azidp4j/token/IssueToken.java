package org.azidp4j.token;

import com.nimbusds.jose.util.Base64URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.authorizationcode.AuthorizationCodeService;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.TokenEndpointAuthMethod;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.scope.ScopeValidator;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.refreshtoken.RefreshToken;
import org.azidp4j.token.refreshtoken.RefreshTokenService;
import org.azidp4j.token.request.InternalTokenRequest;
import org.azidp4j.token.request.TokenRequest;
import org.azidp4j.token.request.TokenRequestParser;
import org.azidp4j.token.response.TokenResponse;
import org.azidp4j.util.MapUtil;

public class IssueToken {

    private final AuthorizationCodeService authorizationCodeService;
    private final AccessTokenService accessTokenService;
    private final ScopeAudienceMapper scopeAudienceMapper;
    private final IDTokenIssuer idTokenIssuer;
    private final RefreshTokenService refreshTokenService;
    private final AzIdPConfig config;
    private final UserPasswordVerifier userPasswordVerifier;
    private final ClientStore clientStore;
    private final ScopeValidator scopeValidator = new ScopeValidator();
    private final TokenRequestParser tokenRequestParser = new TokenRequestParser();

    public IssueToken(
            AzIdPConfig azIdPConfig,
            AuthorizationCodeService authorizationCodeService,
            AccessTokenService accessTokenService,
            IDTokenIssuer idTokenIssuer,
            RefreshTokenService refreshTokenService,
            ScopeAudienceMapper scopeAudienceMapper,
            UserPasswordVerifier userPasswordVerifier,
            ClientStore clientStore) {
        this.authorizationCodeService = authorizationCodeService;
        this.accessTokenService = accessTokenService;
        this.idTokenIssuer = idTokenIssuer;
        this.refreshTokenService = refreshTokenService;
        this.scopeAudienceMapper = scopeAudienceMapper;
        this.config = azIdPConfig;
        this.userPasswordVerifier = userPasswordVerifier;
        this.clientStore = clientStore;
    }

    public TokenResponse issue(TokenRequest request) {
        InternalTokenRequest req;
        try {
            req = tokenRequestParser.parse(request);
        } catch (IllegalArgumentException e) {
            return new TokenResponse(400, Map.of("error", "invalid_request"));
        }

        GrantType grantType;
        if (req.grantType == null) {
            return new TokenResponse(400, Map.of("error", "invalid_request"));
        }
        try {
            grantType = GrantType.of(req.grantType);
        } catch (IllegalArgumentException e) {
            return new TokenResponse(400, Map.of("error", "invalid_request"));
        }
        if (req.authenticatedClientId == null && req.clientId == null) {
            return new TokenResponse(400, Map.of("error", "invalid_request"));
        }
        if (req.authenticatedClientId != null
                && req.clientId != null
                && !Objects.equals(req.authenticatedClientId, req.clientId)) {
            return new TokenResponse(400, Map.of("error", "invalid_request"));
        }
        var clientOpt =
                clientStore.find(req.clientId != null ? req.clientId : req.authenticatedClientId);
        if (clientOpt.isEmpty()) {
            return new TokenResponse(400, Map.of("error", "unauthorized_client"));
        }
        var client = clientOpt.get();
        if (client.tokenEndpointAuthMethod != TokenEndpointAuthMethod.none
                && req.authenticatedClientId == null) {
            // client authentication required
            return new TokenResponse(400, Map.of("error", "invalid_client"));
        }
        if (!client.grantTypes.contains(grantType)) {
            return new TokenResponse(400, Map.of("error", "unsupported_grant_type"));
        }
        switch (grantType) {
            case authorization_code -> {
                var authorizationCodeOpt = authorizationCodeService.consume(req.code);
                if (authorizationCodeOpt.isEmpty()) {
                    accessTokenService.revokeByAuthorizationCode(req.code);
                    refreshTokenService.revokeByAuthorizationCode(req.code);
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
                if (!authorizationCode.redirectUri.equals(req.redirectUri)) {
                    return new TokenResponse(400, Map.of("error", "invalid_grant"));
                }
                if (authorizationCode.codeChallengeMethod != null) {
                    if (req.codeVerifier == null) {
                        return new TokenResponse(400, Map.of("error", "invalid_grant"));
                    }
                    switch (authorizationCode.codeChallengeMethod) {
                        case PLAIN -> {
                            if (!authorizationCode.codeChallenge.equals(req.codeVerifier)) {
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
                            var hash = sha256.digest(req.codeVerifier.getBytes());
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
                                Instant.now().getEpochSecond()
                                        + config.accessTokenExpiration.toSeconds(),
                                Instant.now().getEpochSecond(),
                                scopeAudienceMapper.map(authorizationCode.scope),
                                authorizationCode.code);
                String rt = null;
                if (client.grantTypes.contains(GrantType.refresh_token)) {
                    rt =
                            refreshTokenService.issue(
                                            authorizationCode.sub,
                                            authorizationCode.scope,
                                            authorizationCode.clientId,
                                            Instant.now().getEpochSecond()
                                                    + config.refreshTokenExpiration.toSeconds(),
                                            Instant.now().getEpochSecond(),
                                            scopeAudienceMapper.map(authorizationCode.scope),
                                            authorizationCode.code)
                                    .token;
                }

                if (scopeValidator.contains(authorizationCode.scope, "openid")) {
                    // OIDC
                    var idToken =
                            idTokenIssuer.issue(
                                    authorizationCode.sub,
                                    client.clientId,
                                    authorizationCode.authTime,
                                    authorizationCode.nonce,
                                    at.token,
                                    null,
                                    client.idTokenSignedResponseAlg);
                    if (authorizationCode.state == null) {
                        return new TokenResponse(
                                200,
                                MapUtil.nullRemovedMap(
                                        "access_token",
                                        at.token,
                                        "id_token",
                                        idToken.serialize(),
                                        "refresh_token",
                                        rt,
                                        "token_type",
                                        "bearer",
                                        "expires_in",
                                        config.accessTokenExpiration.toSeconds(),
                                        "scope",
                                        authorizationCode.scope));
                    }
                    return new TokenResponse(
                            200,
                            MapUtil.nullRemovedMap(
                                    "access_token",
                                    at.token,
                                    "id_token",
                                    idToken.serialize(),
                                    "refresh_token",
                                    rt,
                                    "token_type",
                                    "bearer",
                                    "expires_in",
                                    config.accessTokenExpiration.toSeconds(),
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
                                    at.token,
                                    "refresh_token",
                                    rt,
                                    "token_type",
                                    "bearer",
                                    "expires_in",
                                    config.accessTokenExpiration.toSeconds(),
                                    "scope",
                                    authorizationCode.scope,
                                    "state",
                                    authorizationCode.state));
                }
            }
            case password -> {
                var scope = req.scope != null ? req.scope : String.join(" ", config.defaultScope);
                // verify scope
                if (!scopeValidator.hasEnoughScope(scope, client)) {
                    return new TokenResponse(400, Map.of("error", "invalid_scope"));
                }
                // verify user
                if (userPasswordVerifier == null) {
                    throw new AssertionError(
                            "Resource owner password credentials grant needs to set"
                                    + " userPasswordVerifier on AzIdp instance.");
                }
                if (userPasswordVerifier.verify(req.username, req.password)) {
                    var at =
                            accessTokenService.issue(
                                    req.username,
                                    req.scope,
                                    client.clientId,
                                    Instant.now().getEpochSecond()
                                            + config.accessTokenExpiration.toSeconds(),
                                    Instant.now().getEpochSecond(),
                                    scopeAudienceMapper.map(req.scope),
                                    null);
                    String rt = null;
                    if (client.grantTypes.contains(GrantType.refresh_token)) {
                        rt =
                                new RefreshToken(
                                                UUID.randomUUID().toString(),
                                                req.username,
                                                scope,
                                                client.clientId,
                                                scopeAudienceMapper.map(scope),
                                                Instant.now().getEpochSecond()
                                                        + config.refreshTokenExpiration.toSeconds(),
                                                Instant.now().getEpochSecond())
                                        .token;
                    }
                    return new TokenResponse(
                            200,
                            MapUtil.nullRemovedMap(
                                    "access_token",
                                    at.token,
                                    "refresh_token",
                                    rt,
                                    "token_type",
                                    "bearer",
                                    "expires_in",
                                    config.accessTokenExpiration.toSeconds(),
                                    "scope",
                                    scope));
                } else {
                    return new TokenResponse(400, Map.of("error", "invalid_grant"));
                }
            }
            case client_credentials -> {
                var scope = req.scope != null ? req.scope : String.join(" ", config.defaultScope);
                if (client.tokenEndpointAuthMethod == TokenEndpointAuthMethod.none) {
                    return new TokenResponse(400, Map.of("error", "invalid_client"));
                }
                // verify scope
                if (!scopeValidator.hasEnoughScope(scope, client)) {
                    return new TokenResponse(400, Map.of("error", "invalid_scope"));
                }
                var at =
                        accessTokenService.issue(
                                client.clientId,
                                scope,
                                client.clientId,
                                Instant.now().getEpochSecond()
                                        + config.accessTokenExpiration.toSeconds(),
                                Instant.now().getEpochSecond(),
                                scopeAudienceMapper.map(scope),
                                null);
                return new TokenResponse(
                        200,
                        MapUtil.nullRemovedMap(
                                "access_token",
                                at.token,
                                "token_type",
                                "bearer",
                                "expires_in",
                                config.accessTokenExpiration.toSeconds(),
                                "scope",
                                scope));
            }
            case refresh_token -> {
                if (req.refreshToken == null) {
                    return new TokenResponse(400, Map.of("error", "invalid_grant"));
                }
                var rtOpt = refreshTokenService.consume(req.refreshToken);
                if (rtOpt.isEmpty()) {
                    return new TokenResponse(400, Map.of("error", "invalid_grant"));
                }
                var rt = rtOpt.get();
                if (!rt.clientId.equals(client.clientId)) {
                    return new TokenResponse(400, Map.of("error", "invalid_grant"));
                }
                if (rt.expiresAtEpochSec < Instant.now().getEpochSecond()) {
                    return new TokenResponse(400, Map.of("error", "invalid_grant"));
                }
                if (!scopeValidator.hasEnoughScope(req.scope, rt.scope)) {
                    return new TokenResponse(400, Map.of("error", "invalid_scope"));
                }
                var scope = req.scope != null ? req.scope : rt.scope;
                var at =
                        accessTokenService.issue(
                                rt.sub,
                                scope,
                                client.clientId,
                                Instant.now().getEpochSecond()
                                        + config.accessTokenExpiration.toSeconds(),
                                Instant.now().getEpochSecond(),
                                scopeAudienceMapper.map(scope),
                                rt.authorizationCode);
                var newRt =
                        refreshTokenService.issue(
                                rt.sub,
                                scope,
                                rt.clientId,
                                Instant.now().getEpochSecond()
                                        + config.refreshTokenExpiration.toSeconds(),
                                Instant.now().getEpochSecond(),
                                scopeAudienceMapper.map(scope),
                                rt.authorizationCode);
                return new TokenResponse(
                        200,
                        MapUtil.nullRemovedMap(
                                "access_token",
                                at.token,
                                "refresh_token",
                                newRt.token,
                                "token_type",
                                "bearer",
                                "expires_in",
                                config.accessTokenExpiration.toSeconds(),
                                "scope",
                                scope));
            }
            default -> throw new RuntimeException("unsupported grant type");
        }
    }
}
