package org.azidp4j.authorize;

import java.net.URI;
import java.time.Instant;
import java.util.*;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.scope.ScopeValidator;
import org.azidp4j.token.accesstoken.AccessTokenStore;
import org.azidp4j.token.accesstoken.InMemoryAccessToken;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.util.MapUtil;

public class Authorize {

    private final AuthorizationCodeStore authorizationCodeStore;

    private final ClientStore clientStore;

    private final AccessTokenStore accessTokenStore;

    private final ScopeAudienceMapper scopeAudienceMapper;

    private final IDTokenIssuer idTokenIssuer;

    private final AzIdPConfig azIdPConfig;

    private final ScopeValidator scopeValidator = new ScopeValidator();

    public Authorize(
            ClientStore clientStore,
            AuthorizationCodeStore authorizationCodeStore,
            AccessTokenStore accessTokenStore,
            ScopeAudienceMapper scopeAudienceMapper,
            IDTokenIssuer idTokenIssuer,
            AzIdPConfig azIdPConfig) {
        this.clientStore = clientStore;
        this.authorizationCodeStore = authorizationCodeStore;
        this.accessTokenStore = accessTokenStore;
        this.scopeAudienceMapper = scopeAudienceMapper;
        this.idTokenIssuer = idTokenIssuer;
        this.azIdPConfig = azIdPConfig;
    }

    public AuthorizationResponse authorize(InternalAuthorizationRequest authorizationRequest) {

        var responseType = ResponseType.parse(authorizationRequest.responseType);
        if (responseType == null) {
            return new AuthorizationResponse(400);
        }

        var responseMode = ResponseMode.of(authorizationRequest.responseMode, responseType);
        if (responseMode == null) {
            return new AuthorizationResponse(400);
        }

        // validate client
        if (authorizationRequest.clientId == null) {
            return new AuthorizationResponse(400);
        }
        var client = clientStore.find(authorizationRequest.clientId);
        if (client == null) {
            return new AuthorizationResponse(400);
        }

        // validate redirect urls
        if (authorizationRequest.redirectUri == null) {
            return new AuthorizationResponse(400);
        }
        if (!client.redirectUris.contains(authorizationRequest.redirectUri)) {
            return new AuthorizationResponse(400);
        }
        URI redirectUri = null;
        try {
            redirectUri = URI.create(authorizationRequest.redirectUri);
        } catch (IllegalArgumentException e) {
            return new AuthorizationResponse(400);
        }
        if (authorizationRequest.request != null) {
            return new AuthorizationResponse(
                    302,
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "request_not_supported", "state", authorizationRequest.state),
                    responseMode);
        }
        if (authorizationRequest.requestUri != null) {
            return new AuthorizationResponse(
                    302,
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error",
                            "request_uri_not_supported",
                            "state",
                            authorizationRequest.state),
                    responseMode);
        }
        if (authorizationRequest.registration != null) {
            return new AuthorizationResponse(
                    302,
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error",
                            "registration_not_supported",
                            "state",
                            authorizationRequest.state),
                    responseMode);
        }
        // https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
        if (responseType.contains(ResponseType.code)) {
            // validate grant type and response type
            if (!client.grantTypes.contains(GrantType.authorization_code)) {
                // if response type has code, need to allowed authorization_code
                // https://www.rfc-editor.org/rfc/rfc7591.html#section-2.1
                return new AuthorizationResponse(
                        302,
                        redirectUri,
                        MapUtil.nullRemovedStringMap(
                                "error",
                                "unauthorized_client",
                                "state",
                                authorizationRequest.state),
                        responseMode);
            }
        }

        if (responseType.contains(ResponseType.token)
                || responseType.contains(ResponseType.id_token)) {
            // validate grant type and response type
            if (!client.grantTypes.contains(GrantType.implicit)) {
                return new AuthorizationResponse(
                        302,
                        redirectUri,
                        MapUtil.nullRemovedStringMap(
                                "error",
                                "unauthorized_client",
                                "state",
                                authorizationRequest.state),
                        responseMode);
            }
        }

        // validate scope
        if (!scopeValidator.hasEnoughScope(authorizationRequest.scope, client)) {
            return new AuthorizationResponse(
                    302,
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_scope", "state", authorizationRequest.state),
                    responseMode);
        }
        if (authorizationRequest.codeChallenge == null
                && authorizationRequest.codeChallengeMethod != null) {
            return new AuthorizationResponse(
                    302,
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_request", "state", authorizationRequest.state),
                    responseMode);
        }
        ;
        CodeChallengeMethod codeChallengeMethod = null;
        if (authorizationRequest.codeChallengeMethod != null) {
            codeChallengeMethod = CodeChallengeMethod.of(authorizationRequest.codeChallengeMethod);
            if (codeChallengeMethod == null) {
                return new AuthorizationResponse(
                        302,
                        redirectUri,
                        MapUtil.nullRemovedStringMap(
                                "error", "invalid_request", "state", authorizationRequest.state),
                        responseMode);
            }
        }

        Set<Prompt> prompt = Prompt.parse(authorizationRequest.prompt);
        if (prompt == null) {
            // prompt is invalid
            return new AuthorizationResponse(
                    302,
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_request", "state", authorizationRequest.state),
                    responseMode);
        }
        if (prompt.contains(Prompt.none) && prompt.size() != 1) {
            // none with other prompt is invalid
            return new AuthorizationResponse(
                    302,
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_request", "state", authorizationRequest.state),
                    responseMode);
        } else {
            if (prompt.contains(Prompt.none)) {
                if (authorizationRequest.authenticatedUserId == null) {
                    return new AuthorizationResponse(
                            302,
                            redirectUri,
                            MapUtil.nullRemovedStringMap(
                                    "error", "login_required", "state", authorizationRequest.state),
                            responseMode);
                }
                if (!authorizationRequest.consentedScope.containsAll(
                        Arrays.stream(authorizationRequest.scope.split(" ")).toList())) {
                    return new AuthorizationResponse(
                            302,
                            redirectUri,
                            MapUtil.nullRemovedStringMap(
                                    "error",
                                    "consent_required",
                                    "state",
                                    authorizationRequest.state),
                            responseMode);
                }
            }
            if (prompt.contains(Prompt.login)) {
                return new AuthorizationResponse(AdditionalPage.login);
            }
            if (prompt.contains(Prompt.consent)) {
                if (authorizationRequest.authenticatedUserId == null) {
                    return new AuthorizationResponse(AdditionalPage.login);
                } else {
                    return new AuthorizationResponse(AdditionalPage.consent);
                }
            }
            if (prompt.contains(Prompt.select_account)) {
                return new AuthorizationResponse(AdditionalPage.select_account);
            }
            if (authorizationRequest.authenticatedUserId == null) {
                return new AuthorizationResponse(AdditionalPage.login);
            }
            if (!authorizationRequest.consentedScope.containsAll(
                    Arrays.stream(authorizationRequest.scope.split(" ")).toList())) {
                return new AuthorizationResponse(AdditionalPage.consent);
            }
        }

        if (!client.responseTypes.containsAll(responseType)) {
            return new AuthorizationResponse(
                    302,
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error",
                            "unsupported_response_type",
                            "state",
                            authorizationRequest.state),
                    responseMode);
        }

        if (responseType.contains(ResponseType.none)) {
            return new AuthorizationResponse(
                    302,
                    redirectUri,
                    MapUtil.nullRemovedStringMap("state", authorizationRequest.state),
                    responseMode);
        }

        String accessToken = null;
        String tokenType = null;
        String expiresIn = null;
        String scope = null;
        if (responseType.contains(ResponseType.token)) {
            // issue access token
            var at =
                    new InMemoryAccessToken(
                            UUID.randomUUID().toString(),
                            authorizationRequest.authenticatedUserId,
                            authorizationRequest.scope,
                            authorizationRequest.clientId,
                            scopeAudienceMapper.map(authorizationRequest.scope),
                            Instant.now().getEpochSecond() + azIdPConfig.accessTokenExpirationSec);
            accessTokenStore.save(at);
            accessToken = at.getToken();
            tokenType = "bearer";
            expiresIn = String.valueOf(azIdPConfig.accessTokenExpirationSec);
            scope = authorizationRequest.scope;
        }

        if (scopeValidator.contains(authorizationRequest.scope, "openid")) {
            if (authorizationRequest.maxAge != null) {
                try {
                    var maxAge = Integer.parseInt(authorizationRequest.maxAge);
                    if (Instant.now().getEpochSecond() > authorizationRequest.authTime + maxAge) {
                        if (prompt.contains(Prompt.none)) {
                            return new AuthorizationResponse(
                                    302,
                                    redirectUri,
                                    MapUtil.nullRemovedStringMap(
                                            "error",
                                            "login_required",
                                            "state",
                                            authorizationRequest.state),
                                    responseMode);
                        } else {
                            return new AuthorizationResponse(AdditionalPage.login);
                        }
                    }
                } catch (NumberFormatException e) {
                    return new AuthorizationResponse(
                            302,
                            redirectUri,
                            MapUtil.nullRemovedStringMap(
                                    "error",
                                    "invalid_request",
                                    "state",
                                    authorizationRequest.state),
                            responseMode);
                }
            }
        }

        String authorizationCode = null;
        if (responseType.contains(ResponseType.code)) {
            // issue authorization code
            var code =
                    new AuthorizationCode(
                            authorizationRequest.authenticatedUserId,
                            UUID.randomUUID().toString(),
                            authorizationRequest.scope,
                            authorizationRequest.clientId,
                            authorizationRequest.redirectUri,
                            authorizationRequest.state,
                            authorizationRequest.authTime,
                            authorizationRequest.nonce,
                            authorizationRequest.codeChallenge,
                            codeChallengeMethod,
                            Instant.now().getEpochSecond()
                                    + azIdPConfig.authorizationCodeExpirationSec);
            authorizationCodeStore.save(code);
            authorizationCode = code.code;
        }

        String idToken = null;
        if (responseType.contains(ResponseType.id_token)) {
            // validate scope
            if (!scopeValidator.contains(authorizationRequest.scope, "openid")) {
                return new AuthorizationResponse(
                        302,
                        redirectUri,
                        MapUtil.nullRemovedStringMap(
                                "error", "invalid_scope", "state", authorizationRequest.state),
                        responseMode);
            }
            idToken =
                    idTokenIssuer
                            .issue(
                                    authorizationRequest.authenticatedUserId,
                                    authorizationRequest.clientId,
                                    authorizationRequest.authTime,
                                    authorizationRequest.nonce,
                                    accessToken,
                                    authorizationCode,
                                    client.idTokenSignedResponseAlg)
                            .serialize();
        }

        return new AuthorizationResponse(
                302,
                redirectUri,
                MapUtil.nullRemovedStringMap(
                        "access_token",
                        accessToken,
                        "id_token",
                        idToken,
                        "code",
                        authorizationCode,
                        "token_type",
                        tokenType,
                        "expires_in",
                        expiresIn,
                        "scope",
                        scope,
                        "state",
                        authorizationRequest.state),
                responseMode);
    }
}
