package org.azidp4j.authorize;

import java.net.URI;
import java.time.Instant;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.authorizationcode.AuthorizationCodeService;
import org.azidp4j.authorize.request.*;
import org.azidp4j.authorize.response.AuthorizationErrorTypeWithoutRedirect;
import org.azidp4j.authorize.response.AuthorizationResponse;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.scope.ScopeValidator;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.util.MapUtil;

public class Authorize {

    private final AuthorizationCodeService authorizationCodeService;

    private final ScopeAudienceMapper scopeAudienceMapper;

    private final ClientStore clientStore;

    private final AccessTokenService accessTokenService;

    private final IDTokenIssuer idTokenIssuer;

    private final AzIdPConfig config;

    private final ScopeValidator scopeValidator = new ScopeValidator();

    public Authorize(
            ClientStore clientStore,
            AuthorizationCodeService authorizationCodeService,
            ScopeAudienceMapper scopeAudienceMapper,
            AccessTokenService accessTokenService,
            IDTokenIssuer idTokenIssuer,
            AzIdPConfig config) {
        this.clientStore = clientStore;
        this.authorizationCodeService = authorizationCodeService;
        this.scopeAudienceMapper = scopeAudienceMapper;
        this.accessTokenService = accessTokenService;
        this.idTokenIssuer = idTokenIssuer;
        this.config = config;
    }

    public AuthorizationResponse authorize(InternalAuthorizationRequest authorizationRequest) {
        var scope =
                authorizationRequest.scope != null && !authorizationRequest.scope.isEmpty()
                        ? authorizationRequest.scope
                        : String.join(" ", config.defaultScope);
        if (authorizationRequest.authenticatedUserId != null
                && authorizationRequest.authTime == null) {
            throw new AssertionError("When user is authenticated, must set authTime.");
        }
        var responseType = ResponseType.parse(authorizationRequest.responseType);
        if (responseType == null) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.invalid_response_type);
        }

        var responseMode = ResponseMode.of(authorizationRequest.responseMode, responseType);
        if (responseMode == null) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.invalid_response_mode);
        }
        if (!config.responseModesSupported.contains(responseMode)) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.unsupported_response_mode);
        }

        // validate client
        if (authorizationRequest.clientId == null) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.client_id_required);
        }
        var clientOpt = clientStore.find(authorizationRequest.clientId);
        if (clientOpt.isEmpty()) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.client_not_found);
        }

        var client = clientOpt.get();

        // validate redirect urls
        if (authorizationRequest.redirectUri == null) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.invalid_redirect_uri);
        }
        if (!client.redirectUris.contains(authorizationRequest.redirectUri)) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.redirect_uri_not_allowed);
        }
        URI redirectUri;
        try {
            redirectUri = URI.create(authorizationRequest.redirectUri);
        } catch (IllegalArgumentException e) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.invalid_redirect_uri);
        }
        if (authorizationRequest.request != null) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "request_not_supported", "state", authorizationRequest.state),
                    responseMode);
        }
        if (authorizationRequest.requestUri != null) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error",
                            "request_uri_not_supported",
                            "state",
                            authorizationRequest.state),
                    responseMode);
        }
        if (authorizationRequest.registration != null) {
            return AuthorizationResponse.redirect(
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
                return AuthorizationResponse.redirect(
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
                return AuthorizationResponse.redirect(
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
        if (!scopeValidator.hasEnoughScope(scope, client)) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_scope", "state", authorizationRequest.state),
                    responseMode);
        }
        if (authorizationRequest.codeChallenge == null
                && authorizationRequest.codeChallengeMethod != null) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_request", "state", authorizationRequest.state),
                    responseMode);
        }
        CodeChallengeMethod codeChallengeMethod = null;
        if (authorizationRequest.codeChallengeMethod != null) {
            codeChallengeMethod = CodeChallengeMethod.of(authorizationRequest.codeChallengeMethod);
            if (codeChallengeMethod == null) {
                return AuthorizationResponse.redirect(
                        redirectUri,
                        MapUtil.nullRemovedStringMap(
                                "error", "invalid_request", "state", authorizationRequest.state),
                        responseMode);
            }
        } else if (authorizationRequest.codeChallenge != null) {
            codeChallengeMethod = CodeChallengeMethod.S256;
        }

        var display = Display.of(authorizationRequest.display);
        if (display == null) {
            display = Display.page;
        }

        var prompt = Prompt.parse(authorizationRequest.prompt);
        if (prompt == null) {
            // prompt is invalid
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_request", "state", authorizationRequest.state),
                    responseMode);
        }
        if (prompt.contains(Prompt.none) && prompt.size() != 1) {
            // none with other prompt is invalid
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_request", "state", authorizationRequest.state),
                    responseMode);
        } else {
            if (prompt.contains(Prompt.none)) {
                if (authorizationRequest.authenticatedUserId == null) {
                    return AuthorizationResponse.redirect(
                            redirectUri,
                            MapUtil.nullRemovedStringMap(
                                    "error", "login_required", "state", authorizationRequest.state),
                            responseMode);
                }
                if (!authorizationRequest.allScopeConsented()) {
                    return AuthorizationResponse.redirect(
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
                return AuthorizationResponse.additionalPage(
                        Prompt.login, display, client.clientId, scope);
            }
            if (authorizationRequest.authenticatedUserId == null) {
                return AuthorizationResponse.additionalPage(
                        Prompt.login, display, client.clientId, scope);
            }
            if (authorizationRequest.maxAge != null || client.defaultMaxAge != null) {
                try {
                    var maxAge =
                            authorizationRequest.maxAge != null
                                    ? Long.parseLong(authorizationRequest.maxAge)
                                    : client.defaultMaxAge;
                    if (Instant.now().getEpochSecond() > authorizationRequest.authTime + maxAge) {
                        if (prompt.contains(Prompt.none)) {
                            return AuthorizationResponse.redirect(
                                    redirectUri,
                                    MapUtil.nullRemovedStringMap(
                                            "error",
                                            "login_required",
                                            "state",
                                            authorizationRequest.state),
                                    responseMode);
                        } else {
                            return AuthorizationResponse.additionalPage(
                                    Prompt.login, display, client.clientId, scope);
                        }
                    }
                } catch (NumberFormatException e) {
                    return AuthorizationResponse.redirect(
                            redirectUri,
                            MapUtil.nullRemovedStringMap(
                                    "error",
                                    "invalid_request",
                                    "state",
                                    authorizationRequest.state),
                            responseMode);
                }
            }
            if (prompt.contains(Prompt.consent)) {
                return AuthorizationResponse.additionalPage(
                        Prompt.consent, display, client.clientId, scope);
            }
            if (prompt.contains(Prompt.select_account)) {
                return AuthorizationResponse.additionalPage(
                        Prompt.select_account, display, client.clientId, scope);
            }
            if (!authorizationRequest.allScopeConsented()) {
                return AuthorizationResponse.additionalPage(
                        Prompt.consent, display, client.clientId, scope);
            }
        }

        if (!client.responseTypes.contains(responseType)) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error",
                            "unsupported_response_type",
                            "state",
                            authorizationRequest.state),
                    responseMode);
        }

        if (responseType.contains(ResponseType.none)) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap("state", authorizationRequest.state),
                    responseMode);
        }

        String accessToken = null;
        String tokenType = null;
        String expiresIn = null;
        String responseScope = null;
        if (responseType.contains(ResponseType.token)) {
            responseScope = scope;
            // issue access token
            var at =
                    accessTokenService.issue(
                            authorizationRequest.authenticatedUserId,
                            scope,
                            authorizationRequest.clientId,
                            Instant.now().getEpochSecond()
                                    + config.accessTokenExpiration.toSeconds(),
                            Instant.now().getEpochSecond(),
                            scopeAudienceMapper.map(scope),
                            null);
            accessToken = at.getToken();
            tokenType = "bearer";
            expiresIn = String.valueOf(config.accessTokenExpiration.getSeconds());
        }

        String authorizationCode = null;
        if (responseType.contains(ResponseType.code)) {
            // issue authorization code
            var code =
                    authorizationCodeService.issue(
                            authorizationRequest.authenticatedUserId,
                            scope,
                            authorizationRequest.clientId,
                            authorizationRequest.redirectUri,
                            authorizationRequest.state,
                            authorizationRequest.authTime,
                            authorizationRequest.nonce,
                            authorizationRequest.codeChallenge,
                            codeChallengeMethod,
                            Instant.now().getEpochSecond()
                                    + config.authorizationCodeExpiration.toSeconds());
            authorizationCode = code.code;
        }

        String idToken = null;
        if (responseType.contains(ResponseType.id_token)) {
            // validate scope
            if (!scopeValidator.contains(scope, "openid")) {
                return AuthorizationResponse.redirect(
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

        return AuthorizationResponse.redirect(
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
                        responseScope,
                        "state",
                        authorizationRequest.state),
                responseMode);
    }
}
